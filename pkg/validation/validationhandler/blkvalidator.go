/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validationhandler

import (
	"encoding/json"
	"fmt"

	"github.com/bluele/gcache"
	cb "github.com/hyperledger/fabric-protos-go/common"
	gproto "github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/gossip/api"
	gcommon "github.com/hyperledger/fabric/gossip/common"
	discovery2 "github.com/hyperledger/fabric/gossip/discovery"
	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
	"github.com/trustbloc/fabric-peer-ext/pkg/common/txflags"
	"github.com/trustbloc/fabric-peer-ext/pkg/gossip/appdata"
	"github.com/trustbloc/fabric-peer-ext/pkg/roles"
	vcommon "github.com/trustbloc/fabric-peer-ext/pkg/validation/common"
)

var logger = flogging.MustGetLogger("ext_validator")

const validateBlockDataType = "validate-block"

type ValidationRequest struct {
	Payload *gproto.Payload
}

type ValidationResponse struct {
	BlockNumber uint64
	TxFlags     txflags.ValidationFlags
	Err         error
	Endpoint    string // Endpoint is the endpoint of the peer that provided the results.
	Local       bool   // If true then that means the results were generated locally and policy validation is not required
	MSPID       string
	Signature   []byte
	Identity    []byte
}

func (vr *ValidationResponse) String() string {
	if vr.Err == nil {
		return fmt.Sprintf("(MSP: [%s], Endpoint: [%s], Block: %d, TxFlags: %v)", vr.MSPID, vr.Endpoint, vr.BlockNumber, vr.TxFlags)
	}

	return fmt.Sprintf("(MSP: [%s], Endpoint: [%s], Block: %d, Err: %s)", vr.MSPID, vr.Endpoint, vr.BlockNumber, vr.Err)
}

type validatorProvider interface {
	GetValidatorForChannel(channelID string) vcommon.Validator
}

type appDataHandlerRegistry interface {
	Register(dataType string, handler appdata.Handler) error
}

type Provider struct {
	validatorProvider
	handlers gcache.Cache
}

func NewProvider(registry appDataHandlerRegistry, validatorProvider validatorProvider, gossip gossipAdapter) *Provider {
	p := &Provider{
		validatorProvider: validatorProvider,
		handlers: gcache.New(0).LoaderFunc(func(cID interface{}) (interface{}, error) {
			channelID := cID.(string)

			return newHandler(channelID, gossip, validatorProvider.GetValidatorForChannel(channelID)), nil
		}).Build(),
	}

	if roles.IsValidator() {
		logger.Info("Registering block validation request handler")

		if err := registry.Register(validateBlockDataType, p.handleValidateBlockRequest); err != nil {
			// Should never happen
			panic(err)
		}
	}

	return p
}

func (p *Provider) handleValidateBlockRequest(channelID string, request *gproto.AppDataRequest) ([]byte, error) {
	req := &ValidationRequest{}
	err := json.Unmarshal(request.Request, req)
	if err != nil {
		return nil, err
	}

	// If currentBlockHeight == req.blockNumber then we can immediately validate
	// If currentBlockHeight < req.blockNumber then queue the block for validation (or reject the request?)
	// If currentBlockHeight > req.blockNumber then we have already committed the block, so return the results from the committed block

	//logger.Infof("[%s] Received validation request for block %d", s.chainID, block.Header.Number)
	//
	//currentHeight, err := s.ledger.LedgerHeight()
	//if err != nil {
	//	logger.Errorf("Error getting height from DB for channel [%s]: %s", s.chainID, errors.WithStack(err))
	//}
	//if block.Header.Number == currentHeight {
	//	logger.Infof("[%s] Validating block [%d] with %d transaction(s)", s.chainID, block.Header.Number, len(block.Data.Data))
	//	s.ledger.ValidatePartialBlock(s.ctxProvider.Create(block.Header.Number), block)
	//} else if block.Header.Number > currentHeight {
	//	logger.Infof("[%s] Block [%d] with %d transaction(s) cannot be validated yet since our ledger height is %d. Adding to cache.", s.chainID, block.Header.Number, len(block.Data.Data), currentHeight)
	//	s.pendingValidations.Add(block)
	//} else {
	//	logger.Infof("[%s] Block [%d] will not be validated since the block has already been committed. Our ledger height is %d.", s.chainID, block.Header.Number, currentHeight)
	//}

	h, err := p.handlers.Get(channelID)
	if err != nil {
		// Should never happen
		panic(err)
	}

	results := h.(*handler).Validate(req.Block)

	return json.Marshal(results)
}

type handler struct {
	*discovery.Discovery
	validator vcommon.Validator
	channel   string
}

type gossipAdapter interface {
	PeersOfChannel(id gcommon.ChannelID) []discovery2.NetworkMember
	SelfMembershipInfo() discovery2.NetworkMember
	IdentityInfo() api.PeerIdentitySet
}

func newHandler(channelID string, gossip gossipAdapter, validator vcommon.Validator) *handler {
	return &handler{
		Discovery: discovery.New(channelID, gossip),
		validator: validator,
		channel:   channelID,
	}
}

func (h *handler) Validate(block *cb.Block) *ValidationResponse {
	results, err := h.validator.Validate(block)

	return &ValidationResponse{
		BlockNumber: block.Header.Number,
		TxFlags:     results,
		Err:         err,
		Endpoint:    h.Self().Endpoint,
		MSPID:       h.Self().MSPID,
		Signature:   nil,
		Identity:    nil,
	}
}

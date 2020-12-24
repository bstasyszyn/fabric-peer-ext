/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validationhandler

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bluele/gcache"
	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	gproto "github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/hyperledger/fabric/common/flogging"
	xgossipapi "github.com/hyperledger/fabric/extensions/gossip/api"
	"github.com/hyperledger/fabric/gossip/api"
	"github.com/hyperledger/fabric/gossip/comm"
	gcommon "github.com/hyperledger/fabric/gossip/common"
	discovery2 "github.com/hyperledger/fabric/gossip/discovery"
	"github.com/hyperledger/fabric/msp"
	"github.com/pkg/errors"
	extcommon "github.com/trustbloc/fabric-peer-ext/pkg/common"
	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
	"github.com/trustbloc/fabric-peer-ext/pkg/config"
	"github.com/trustbloc/fabric-peer-ext/pkg/gossip/appdata"
	"github.com/trustbloc/fabric-peer-ext/pkg/roles"
	vcommon "github.com/trustbloc/fabric-peer-ext/pkg/validation/common"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy"
)

var logger = flogging.MustGetLogger("ext_validation")

const ValidateBlockDataType = "validate-block"

type validatorProvider interface {
	GetValidatorForChannel(channelID string) vcommon.Validator
}

type appDataHandlerRegistry interface {
	Register(dataType string, handler appdata.Handler) error
}

type dataRetriever interface {
	Retrieve(ctxt context.Context, request *appdata.Request, responseHandler appdata.ResponseHandler, allSet appdata.AllSet, opts ...appdata.Option) (extcommon.Values, error)
}

type gossipProvider interface {
	GetGossipService() xgossipapi.GossipService
}

type identityProvider interface {
	GetDefaultSigningIdentity() (msp.SigningIdentity, error)
}

type blockPublisherProvider interface {
	ForChannel(channelID string) xgossipapi.BlockPublisher
}

type contextProvider interface {
	ContextForBlock(channelID string, blockNum uint64) (context.Context, error)
}

type Provider struct {
	handlers gcache.Cache
}

func NewProvider(hr appDataHandlerRegistry, vp validatorProvider, gp gossipProvider, ip identityProvider, bpp blockPublisherProvider, cp contextProvider) *Provider {
	logger.Info("Creating validation handler provider")

	p := &Provider{
		handlers: gcache.New(0).LoaderFunc(func(cID interface{}) (interface{}, error) {
			channelID := cID.(string)

			return newHandler(channelID, gp.GetGossipService(), vp.GetValidatorForChannel(channelID), ip, bpp.ForChannel(channelID), cp), nil
		}).Build(),
	}

	if config.IsDistributedValidationEnabled() && roles.IsValidator() && !roles.IsCommitter() {
		logger.Info("Registering block validation request handler")

		if err := hr.Register(ValidateBlockDataType, p.handleValidateRequest); err != nil {
			// Should never happen
			panic(err)
		}
	}

	return p
}

func (p *Provider) Close() {
	for _, h := range p.handlers.GetALL() {
		h.(*handler).Close()
	}
}

func (p *Provider) SendValidationRequest(channelID string, req *vcommon.ValidationRequest) {
	if err := p.getHandler(channelID).sendValidationRequest(req); err != nil {
		logger.Errorf("[%s] Error sending validation request: %s", channelID, err)
	}
}

func (p *Provider) ValidatePending(channelID string, blockNum uint64) {
	p.getHandler(channelID).validatePending(blockNum)
}

func (p *Provider) handleValidateRequest(channelID string, req *gproto.AppDataRequest, responder appdata.Responder) {
	p.getHandler(channelID).Validate(req, responder)
}

func (p *Provider) getHandler(channelID string) *handler {
	h, err := p.handlers.Get(channelID)
	if err != nil {
		// Should never happen
		panic(err)
	}

	return h.(*handler)
}

type handler struct {
	*discovery.Discovery
	xgossipapi.BlockPublisher
	validator vcommon.Validator
	dataRetriever
	channelID    string
	requestChan  chan *vcommon.ValidationRequest
	ip           identityProvider
	requestCache *requestCache
	cp           contextProvider
}

type gossipAdapter interface {
	PeersOfChannel(id gcommon.ChannelID) []discovery2.NetworkMember
	SelfMembershipInfo() discovery2.NetworkMember
	IdentityInfo() api.PeerIdentitySet
	Send(msg *gproto.GossipMessage, peers ...*comm.RemotePeer)
}

func newHandler(channelID string, gossip gossipAdapter, validator vcommon.Validator, ip identityProvider, bp xgossipapi.BlockPublisher, cp contextProvider) *handler {
	h := &handler{
		Discovery:      discovery.New(channelID, gossip),
		BlockPublisher: bp,
		validator:      validator,
		channelID:      channelID,
		requestChan:    make(chan *vcommon.ValidationRequest, 10), // TODO: Make buffer configurable
		dataRetriever:  appdata.NewRetriever(channelID, gossip, 1, 5),
		ip:             ip,
		requestCache:   newRequestCache(channelID),
		cp:             cp,
	}

	go h.dispatchValidationRequests()

	return h
}

func (h *handler) Close() {
	logger.Infof("[%s] Closing handler", h.channelID)

	close(h.requestChan)
}

func (h *handler) Validate(req *gproto.AppDataRequest, responder appdata.Responder) {
	block := &cb.Block{}
	err := proto.Unmarshal(req.Request, block)
	if err != nil {
		logger.Errorf("[%s] Error unmarshalling block: %s", h.channelID, err)

		return
	}

	logger.Debugf("[%s] Handling validation request for block %d", h.channelID, block.Header.Number)

	currentHeight := h.LedgerHeight()

	if block.Header.Number == currentHeight {
		logger.Infof("[%s] Validating block [%d] with %d transaction(s)", h.channelID, block.Header.Number, len(block.Data.Data))

		ctx, err := h.cp.ContextForBlock(h.channelID, block.Header.Number)
		if err != nil {
			logger.Errorf("[%s] Unable to validate block %d: %s", h.channelID, block.Header.Number, err)

			return
		}

		h.validate(ctx, block, responder)
	} else if block.Header.Number > currentHeight {
		logger.Infof("[%s] Block [%d] with %d transaction(s) cannot be validated yet since our ledger height is %d. Adding to cache.", h.channelID, block.Header.Number, len(block.Data.Data), currentHeight)

		h.requestCache.Add(block, responder)
	} else {
		logger.Infof("[%s] Block [%d] will not be validated since the block has already been committed. Our ledger height is %d.", h.channelID, block.Header.Number, currentHeight)
	}
}

func (h *handler) validate(ctx context.Context, block *cb.Block, responder appdata.Responder) {
	results, err := h.validator.ValidatePartial(ctx, block)

	var signature, identity []byte

	if err != nil {
		logger.Warningf("[%s] Error validating partial block %d: %s", block.Header.Number, err)
	} else {
		logger.Debugf("[%s] Done validating partial block %d", h.channelID, block.Header.Number)

		signature, identity, err = h.signValidationResults(block.Header.Number, results)
		if err != nil {
			logger.Errorf("Error signing validation results: %s", err)
		}
	}

	valResults := &validationpolicy.ValidationResults{
		BlockNumber: block.Header.Number,
		TxFlags:     results,
		Err:         err,
		Endpoint:    h.Self().Endpoint,
		MSPID:       h.Self().MSPID,
		Signature:   signature,
		Identity:    identity,
	}

	resBytes, err := json.Marshal(valResults)
	if err != nil {
		logger.Errorf("[%s] Error marshalling results: %s", h.channelID, err)

		return
	}

	responder.Respond(resBytes)
}

func (h *handler) validatePending(blockNum uint64) {
	logger.Debugf("[%s] Checking for pending request for block %d", h.channelID, blockNum)

	req := h.requestCache.Remove(blockNum)
	if req != nil {
		logger.Infof("[%s] Validating pending request for block %d", h.channelID, blockNum)

		ctx, err := h.cp.ContextForBlock(h.channelID, blockNum)
		if err != nil {
			logger.Errorf("[%s] Unable to validate pending block %d: %s", h.channelID, blockNum, err)

			return
		}

		h.validate(ctx, req.block, req.responder)
	} else {
		logger.Debugf("[%s] Pending request not found for block %d", h.channelID, blockNum)
	}
}

func (h *handler) sendValidationRequest(req *vcommon.ValidationRequest) error {
	blockNum := req.Block.Header.Number

	logger.Debugf("[%s] Sending validation request for block %d", h.channelID, blockNum)

	ctx, err := h.cp.ContextForBlock(h.channelID, blockNum)
	if err != nil {
		return errors.WithMessagef(err, "unable to send validation request for block %d", blockNum)
	}

	validatingPeers, err := h.validator.GetValidatingPeers(req.Block)
	if err != nil {
		return errors.WithMessagef(err, "unable to send validation request for block %d", blockNum)
	}

	if !validatingPeers.ContainsRemote() {
		logger.Infof("[%s] There are no remote validating peers for block %d", h.channelID, blockNum)

		return nil
	}

	mapPeerToIdx := make(map[string]int)

	for i, m := range validatingPeers {
		mapPeerToIdx[m.Endpoint] = i
	}

	startTime := time.Now()

	// The resulting value doesn't matter since we send the partial results immediately to the committer as they are received
	_, err = h.Retrieve(
		ctx,
		&appdata.Request{
			DataType: ValidateBlockDataType,
			Payload:  req.BlockBytes,
		},
		func(response []byte) (extcommon.Values, error) {
			vr := &validationpolicy.ValidationResults{}
			if err := json.Unmarshal(response, vr); err != nil {
				return nil, err
			}

			logger.Infof("[%s] Got validation response from %s for block %d in %s", h.channelID, vr.Endpoint, vr.BlockNumber, time.Since(startTime))

			// Immediately submit the results so that the committer can merge the results
			h.validator.SubmitValidationResults(vr)

			values := make(extcommon.Values, len(mapPeerToIdx))

			idx, ok := mapPeerToIdx[vr.Endpoint]
			if !ok {
				logger.Warningf("[%s] Peer index for %s not found for block %d", h.channelID, vr.Endpoint, vr.BlockNumber)
			} else {
				logger.Debugf("[%s] Using peer index %d for %s for block %d", h.channelID, idx, vr.Endpoint, vr.BlockNumber)
			}

			values[idx] = vr

			return values, nil
		},
		func(values extcommon.Values) bool {
			allSet := values.AllSet()
			if allSet {
				logger.Debugf("[%s] Got all validation responses for block %d", h.channelID, blockNum)

				return true
			}

			logger.Debugf("[%s] Did not get all validation responses for block %d", h.channelID, blockNum)

			return false
		},
		appdata.WithPeerFilter(func(member *discovery.Member) bool {
			if validatingPeers.Contains(member) {
				logger.Infof("[%s] Sending validation request for block %d to %s", h.channelID, blockNum, member.Endpoint)

				return true
			}

			logger.Debugf("[%s] Not sending validation request for block %d to %s", h.channelID, blockNum, member.Endpoint)

			return false
		}),
	)

	return err
}

func (h *handler) submitValidationRequests(req *vcommon.ValidationRequest) {
	logger.Debugf("[%s] Submitting validation request for block %d", h.channelID, req.Block.Header.Number)

	h.requestChan <- req
}

func (h *handler) dispatchValidationRequests() {
	logger.Infof("[%s] Starting validation dispatcher", h.channelID)

	for req := range h.requestChan {
		if err := h.sendValidationRequest(req); err != nil {
			logger.Errorf("[%s] Error sending validation request: %s", h.channelID, err)
		}
	}

	logger.Infof("[%s] Validation dispatcher shutting down", h.channelID)
}

func (h *handler) signValidationResults(blockNum uint64, txFlags []byte) ([]byte, []byte, error) {
	logger.Infof("[%s] Signing validation results for block %d", h.channelID, blockNum)

	signer, err := h.ip.GetDefaultSigningIdentity()
	if err != nil {
		return nil, nil, err
	}

	// serialize the signing identity
	identityBytes, err := signer.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not serialize the signing identity")
	}

	// sign the concatenation of the block number, results, and the serialized signer identity with this peer's key
	signature, err := signer.Sign(validationpolicy.GetDataToSign(blockNum, txFlags, identityBytes))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not sign the proposal response payload")
	}

	return signature, identityBytes, nil
}

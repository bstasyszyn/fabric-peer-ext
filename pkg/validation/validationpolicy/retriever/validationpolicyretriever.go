/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package retriever

import (
	"sync"

	"github.com/bluele/gcache"
	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/pkg/errors"
	extstatedb "github.com/trustbloc/fabric-peer-ext/pkg/statedb"

	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy"
)

var logger = flogging.MustGetLogger("ext_validation")

const (
	channelConfigKey    = "resourcesconfigtx.CHANNEL_CONFIG_KEY"
	validationPolicyKey = "Validation"
	peerNamespace       = ""
)

type stateDBProvider interface {
	StateDBForChannel(channelID string) extstatedb.StateDB
}

type Provider struct {
	retrievers gcache.Cache
}

func NewProvider(stateDBProvider stateDBProvider) *Provider {
	logger.Info("Creating validation policy retriever provider")

	return &Provider{
		retrievers: gcache.New(0).LoaderFunc(func(cID interface{}) (interface{}, error) {
			channelID := cID.(string)

			return newPolicyRetriever(channelID, stateDBProvider.StateDBForChannel(channelID)), nil
		}).Build(),
	}
}

func (p *Provider) PolicyRetrieverForChannel(channelID string) validationpolicy.PolicyRetriever {
	r, err := p.retrievers.Get(channelID)
	if err != nil {
		// Should never happen
		panic(err)
	}

	return r.(*policyRetriever)
}

type policyRetriever struct {
	lock      sync.RWMutex
	channelID string
	stateDB   extstatedb.StateDB
}

func newPolicyRetriever(channelID string, stateDB extstatedb.StateDB) *policyRetriever {
	return &policyRetriever{
		channelID: channelID,
		stateDB:   stateDB,
	}
}

// GetPolicyBytes returns the validation policy bytes from the config block
// TODO: Should cache
func (r *policyRetriever) GetPolicyBytes() ([]byte, bool, error) {
	serializedConfig, err := r.stateDB.GetState(peerNamespace, channelConfigKey)
	if err != nil {
		return nil, false, err
	}

	if serializedConfig == nil {
		return nil, false, nil
	}

	conf := &cb.Config{}
	err = proto.Unmarshal(serializedConfig, conf)
	if err != nil {
		return nil, false, errors.New("error retrieving persisted channelID config")
	}

	appGroup, ok := conf.GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey]
	if !ok {
		return nil, false, nil
	}

	policy, ok := appGroup.GetPolicies()[validationPolicyKey]
	if !ok {
		return nil, false, nil
	}

	return policy.GetPolicy().GetValue(), true, nil
}

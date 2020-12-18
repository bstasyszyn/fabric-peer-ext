/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validationhandler

import (
	"sync"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/pkg/errors"

	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy"
)

const (
	channelConfigKey    = "resourcesconfigtx.CHANNEL_CONFIG_KEY"
	validationPolicyKey = "Validation"
	peerNamespace       = ""
)

type policyRetriever struct {
	lock      sync.RWMutex
	channelID string
	ledger    ledger.PeerLedger
	listener  validationpolicy.ConfigUpdateListener
}

func newPolicyRetriever(channelID string, ledger ledger.PeerLedger) *policyRetriever {
	return &policyRetriever{
		channelID: channelID,
		ledger:    ledger,
	}
}

// GetPolicyBytes returns the validation policy bytes from the config block
func (r *policyRetriever) GetPolicyBytes() ([]byte, bool, error) {
	return getValidationPolicy(r.channelID, r.ledger)
}

// AddListener adds the given listener that is invoked when the config is updated
func (r *policyRetriever) AddListener(listener validationpolicy.ConfigUpdateListener) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.listener = listener
}

func (r *policyRetriever) configUpdated(*channelconfig.Bundle) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.listener != nil {
		logger.Infof("Informing validation policy listener that the config has been updated")
		r.listener()
	}
}

func getValidationPolicy(channelID string, ledger ledger.PeerLedger) ([]byte, bool, error) {
	conf, err := retrievePersistedChannelConfig(ledger)
	if err != nil {
		return nil, false, errors.New("error retrieving persisted channel config")
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

func deserialize(serializedConf []byte) (*cb.Config, error) {
	conf := &cb.Config{}
	if err := proto.Unmarshal(serializedConf, conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// retrievePersistedChannelConfig retrieves the persisted channel config from statedb
func retrievePersistedChannelConfig(ledger ledger.PeerLedger) (*cb.Config, error) {
	// FIXME: Use state DB retriever instead of query executor
	qe, err := ledger.NewQueryExecutor()
	if err != nil {
		return nil, err
	}
	defer qe.Done()

	return retrieveConfig(qe, channelConfigKey)
}

// TODO: Need to cache
func retrieveConfig(queryExecuter ledger.QueryExecutor, key string) (*cb.Config, error) {
	serializedConfig, err := queryExecuter.GetState(peerNamespace, key)
	if err != nil {
		return nil, err
	}
	if serializedConfig == nil {
		return nil, nil
	}
	return deserialize(serializedConfig)
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validation

import (
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/core/committer/txvalidator"
	"github.com/hyperledger/fabric/core/committer/txvalidator/plugin"
	"github.com/hyperledger/fabric/core/committer/txvalidator/v20/plugindispatcher"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/privacyenabledstate"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/rwsetutil"
	validationapi "github.com/hyperledger/fabric/extensions/validation/api"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation"
)

// postOrderSimulatorProvider provides access to a tx simulator for executing post order non-endorser transactions
type postOrderSimulatorProvider interface {
	NewTxSimulator(txid string) (ledger.TxSimulator, error)
}

// NewCommitBatchPreparer constructs a validator that internally manages state-based validator and in addition
// handles the tasks that are agnostic to a particular validation scheme such as parsing the block and handling the pvt data
func NewCommitBatchPreparer(
	postOrderSimulatorProvider postOrderSimulatorProvider,
	db *privacyenabledstate.DB,
	customTxProcessors map[common.HeaderType]ledger.CustomTxProcessor,
	hashFunc rwsetutil.HashFunc,
) validationapi.CommitBatchPreparer {
	return validation.NewCommitBatchPreparer(
		postOrderSimulatorProvider,
		db,
		customTxProcessors,
		hashFunc)
}

func NewValidator(
	channelID string,
	sem validation.Semaphore,
	cr validation.ChannelResources,
	ler validation.LedgerResources,
	lcr plugindispatcher.LifecycleResources,
	cor plugindispatcher.CollectionResources,
	pm plugin.Mapper,
	channelPolicyManagerGetter policies.ChannelPolicyManagerGetter,
	cryptoProvider bccsp.BCCSP,
) txvalidator.Validator {
	return validation.NewValidator(channelID, sem, cr, ler, lcr, cor, pm, channelPolicyManagerGetter, cryptoProvider)
}

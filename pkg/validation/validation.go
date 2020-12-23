/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validation

import (
	"context"
	"time"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/core/committer/txvalidator"
	"github.com/hyperledger/fabric/core/committer/txvalidator/plugin"
	validatorv14 "github.com/hyperledger/fabric/core/committer/txvalidator/v14"
	validatorv20 "github.com/hyperledger/fabric/core/committer/txvalidator/v20"
	"github.com/hyperledger/fabric/core/committer/txvalidator/v20/plugindispatcher"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/privacyenabledstate"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/rwsetutil"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/validation"
	"github.com/hyperledger/fabric/extensions/validation/api"
	extvalidation "github.com/hyperledger/fabric/extensions/validation/api"
	"github.com/hyperledger/fabric/msp"
	"github.com/trustbloc/fabric-peer-ext/pkg/config"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validator"
)

var logger = flogging.MustGetLogger("ext_validation")

type CommitBatchPreparer struct {
	target api.CommitBatchPreparer
}

// postOrderSimulatorProvider provides access to a tx simulator for executing post order non-endorser transactions
type postOrderSimulatorProvider interface {
	NewTxSimulator(txid string) (ledger.TxSimulator, error)
}

// NewCommitBatchPreparer constructs a validator that internally manages state-based validator and in addition
// handles the tasks that are agnostic to a particular validation scheme such as parsing the block and handling the pvt data
// FIXME: Do we need this???
func NewCommitBatchPreparer(
	postOrderSimulatorProvider postOrderSimulatorProvider,
	db *privacyenabledstate.DB,
	customTxProcessors map[common.HeaderType]ledger.CustomTxProcessor,
	hashFunc rwsetutil.HashFunc,
) extvalidation.CommitBatchPreparer {
	return &CommitBatchPreparer{
		target: validation.NewCommitBatchPreparer(
			postOrderSimulatorProvider,
			db,
			customTxProcessors,
			hashFunc),
	}

}

func (p *CommitBatchPreparer) ValidateAndPrepareBatch(blockAndPvtdata *ledger.BlockAndPvtData, doMVCCValidation bool) (*privacyenabledstate.UpdateBatch, []*validation.TxStatInfo, error) {
	startTime := time.Now()

	logger.Infof("Starting ValidateAndPrepareBatch %d transactions and %d private data and %d missing private data ...", len(blockAndPvtdata.Block.Data.Data), len(blockAndPvtdata.PvtData), len(blockAndPvtdata.MissingPvtData))

	batch, info, err := p.target.ValidateAndPrepareBatch(blockAndPvtdata, doMVCCValidation)

	logger.Infof("... ValidateAndPrepareBatch took %s for %d transactions and %d private data %d missing private data", time.Since(startTime), len(blockAndPvtdata.Block.Data.Data), len(blockAndPvtdata.PvtData), len(blockAndPvtdata.MissingPvtData))

	return batch, info, err
}

// Semaphore provides to the validator means for synchronisation
type Semaphore interface {
	// Acquire implements semaphore-like acquire semantics
	Acquire(ctx context.Context) error

	// Release implements semaphore-like release semantics
	Release()
}

// ChannelResources provides access to channel artefacts or
// functions to interact with them
type ChannelResources interface {
	// MSPManager returns the MSP manager for this channel
	MSPManager() msp.MSPManager

	// Apply attempts to apply a configtx to become the new config
	Apply(configtx *common.ConfigEnvelope) error

	// GetMSPIDs returns the IDs for the application MSPs
	// that have been defined in the channel
	GetMSPIDs() []string

	// Capabilities defines the capabilities for the application portion of this channel
	Capabilities() channelconfig.ApplicationCapabilities

	// Ledger returns the ledger associated with this validator
	Ledger() ledger.PeerLedger
}

// LedgerResources provides access to ledger artefacts or
// functions to interact with them
type LedgerResources interface {
	// GetTransactionByID retrieves a transaction by id
	GetTransactionByID(txID string) (*peer.ProcessedTransaction, error)

	// NewQueryExecutor gives handle to a query executor.
	// A client can obtain more than one 'QueryExecutor's for parallel execution.
	// Any synchronization should be performed at the implementation level if required
	NewQueryExecutor() (ledger.QueryExecutor, error)
}

func NewValidator(
	channelID string,
	sem Semaphore,
	cr ChannelResources,
	ler LedgerResources,
	lcr plugindispatcher.LifecycleResources,
	cor plugindispatcher.CollectionResources,
	pm plugin.Mapper,
	channelPolicyManagerGetter policies.ChannelPolicyManagerGetter,
	cryptoProvider bccsp.BCCSP,
) txvalidator.Validator {
	var v2Validator txvalidator.Validator

	if config.IsDistributedValidationEnabled() {
		logger.Infof("[%s] Creating distributed validator for V20 validation", channelID)

		v2Validator = validator.GetProvider().CreateValidator(channelID, sem, cr, ler, lcr, cor, pm, channelPolicyManagerGetter, cryptoProvider)
	} else {
		v2Validator = validatorv20.NewTxValidator(channelID, sem, cr, ler, lcr, cor, pm, channelPolicyManagerGetter, cryptoProvider)
	}

	return &txvalidator.ValidationRouter{
		CapabilityProvider: cr,
		V14Validator:       validatorv14.NewTxValidator(channelID, sem, cr, pm, cryptoProvider),
		V20Validator:       v2Validator,
	}
}

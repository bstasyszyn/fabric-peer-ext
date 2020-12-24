/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/cauthdsl"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/core/committer/txvalidator"
	"github.com/hyperledger/fabric/core/committer/txvalidator/plugin"
	validatorv20 "github.com/hyperledger/fabric/core/committer/txvalidator/v20"
	"github.com/hyperledger/fabric/core/committer/txvalidator/v20/plugindispatcher"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/extensions/endorser/api"
	gossipapi "github.com/hyperledger/fabric/extensions/gossip/api"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	"github.com/trustbloc/fabric-peer-ext/pkg/config"

	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
	"github.com/trustbloc/fabric-peer-ext/pkg/common/txflags"
	vcommon "github.com/trustbloc/fabric-peer-ext/pkg/validation/common"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationresults"
)

var logger = flogging.MustGetLogger("ext_validation")

// ignoreCancel is a cancel function that does nothing
var ignoreCancel = func() {}

var instance *Provider
var mutex sync.RWMutex

func GetProvider() *Provider {
	mutex.RLock()
	defer mutex.RUnlock()

	return instance
}

type semaphore interface {
	// Acquire implements semaphore-like acquire semantics
	Acquire(ctx context.Context) error

	// Release implements semaphore-like release semantics
	Release()
}

type channelResources interface {
	MSPManager() msp.MSPManager
	Apply(configtx *common.ConfigEnvelope) error
	GetMSPIDs() []string
	Capabilities() channelconfig.ApplicationCapabilities
}

type ledgerResources interface {
	GetTransactionByID(txID string) (*peer.ProcessedTransaction, error)
	NewQueryExecutor() (ledger.QueryExecutor, error)
}

type validator struct {
	*validatorv20.TxValidator
	*discovery.Discovery
	channelID             string
	resultsCache          *validationresults.Cache
	resultsChan           chan *validationpolicy.ValidationResults
	validationPolicy      *validationpolicy.Policy
	validationMinWaitTime time.Duration
}

type identityDeserializerProvider interface {
	GetIdentityDeserializer(channelID string) msp.IdentityDeserializer
}

type Providers struct {
	Gossip             gossipProvider
	Idp                identityDeserializerProvider
	Prp                policyRetrieverProvider
	Bpp                api.BlockPublisherProvider
	ValidatorDiscovery validationpolicy.ValidatorDiscovery
}

type Provider struct {
	*Providers
	mutex      sync.RWMutex
	validators map[string]*validator
}

type gossipProvider interface {
	GetGossipService() gossipapi.GossipService
}

type policyRetrieverProvider interface {
	PolicyRetrieverForChannel(channelID string) validationpolicy.PolicyRetriever
}

func NewProvider(providers *Providers) *Provider {
	logger.Info("Creating validator provider")

	mutex.Lock()
	defer mutex.Unlock()

	instance = &Provider{
		Providers:  providers,
		validators: make(map[string]*validator),
	}

	return instance
}

func (p *Provider) CreateValidator(
	channelID string,
	sem semaphore,
	cr channelResources,
	ler ledgerResources,
	lcr plugindispatcher.LifecycleResources,
	cor plugindispatcher.CollectionResources,
	pm plugin.Mapper,
	channelPolicyManagerGetter policies.ChannelPolicyManagerGetter,
	cryptoProvider bccsp.BCCSP) txvalidator.Validator {

	p.mutex.Lock()
	defer p.mutex.Unlock()

	if _, exists := p.validators[channelID]; exists {
		// Should never happen
		panic(fmt.Errorf("a validator already exists for channel [%s]", channelID))
	}

	disc := discovery.New(channelID, p.Gossip.GetGossipService())

	v := &validator{
		channelID:    channelID,
		Discovery:    disc,
		resultsChan:  make(chan *validationpolicy.ValidationResults, 10), // TODO: Configurable buffer size?
		resultsCache: validationresults.NewCache(),
		TxValidator:  validatorv20.NewTxValidator(channelID, sem, cr, ler, lcr, cor, pm, channelPolicyManagerGetter, cryptoProvider),
		validationPolicy: validationpolicy.New(
			channelID, disc,
			cauthdsl.NewPolicyProvider(p.Idp.GetIdentityDeserializer(channelID)),
			p.Prp.PolicyRetrieverForChannel(channelID),
			p.Bpp.ForChannel(channelID),
			p.ValidatorDiscovery,
		),
		validationMinWaitTime: config.GetValidationWaitTime(),
	}

	p.validators[channelID] = v

	return v
}

func (p *Provider) GetValidatorForChannel(channelID string) vcommon.Validator {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.validators[channelID]
}

func (v *validator) GetValidatingPeers(block *common.Block) (discovery.PeerGroup, error) {
	return v.validationPolicy.GetValidatingPeers(block)
}

func (v *validator) Validate(block *common.Block) error {
	startValidation := time.Now() // timer to log Validate block duration
	logger.Debugf("[%s] Starting validation for block [%d]", v.channelID, block.Header.Number)

	// Initialize the flags all to TxValidationCode_NOT_VALIDATED
	protoutil.InitBlockMetadata(block)
	block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER] = txflags.New(len(block.Data.Data))

	validatingPeers, err := v.validationPolicy.GetValidatingPeers(block)
	if err != nil {
		logger.Warningf("[%s] Error getting validating peers for block %d: %s", v.channelID, block.Header.Number, err)
	} else if validatingPeers.ContainsLocal() {
		go v.validateLocal(block)
	}

	flags := newTxFlags(block)
	err = v.waitForValidationResults(ignoreCancel, block.Header.Number, flags, v.validationMinWaitTime)
	if err != nil {
		logger.Warningf("[%s] Got error in validation response for block %d: %s", v.channelID, block.Header.Number, err)
		return err
	}

	notValidated := flags.unvalidatedMap()
	if len(notValidated) > 0 {
		ctx, cancel := context.WithCancel(context.Background())

		// Haven't received results for some of the transactions. Validate the remaining ones.
		go v.validateRemaining(ctx, block, notValidated)

		// Wait forever for a response
		err := v.waitForValidationResults(cancel, block.Header.Number, flags, time.Hour)
		if err != nil {
			logger.Warningf("[%s] Got error validating remaining transactions in block %d: %s", v.channelID, block.Header.Number, err)
			return err
		}
	}

	if !flags.allValidated() {
		logger.Errorf("[%s] Not all transactions in block %d were validated", v.channelID, block.Header.Number)
		return errors.Errorf("Not all transactions in block %d were validated", block.Header.Number)
	}

	// we mark invalid any transaction that has a txid
	// which is equal to that of a previous tx in this block
	// FIXME:
	//flags.markTXIdDuplicates()
	//markTXIdDuplicates(txidArray, txsfltr)

	// make sure no transaction has skipped validation
	if !flags.allValidated() {
		return errors.Errorf("not all transactions in block %d were validated", block.Header.Number)
	}

	// Initialize metadata structure
	protoutil.InitBlockMetadata(block)

	block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER] = flags.value()

	logger.Infof("[%s] Validated block [%d] in %dms", v.channelID, block.Header.Number, time.Since(startValidation).Milliseconds())

	return nil
}

// ValidatePartial partially validates the block and sends the validation results over Gossip
// NOTE: This function should only be called by validators and not committers.
func (v *validator) ValidatePartial(ctx context.Context, block *common.Block) (txflags.ValidationFlags, error) {
	//stopWatch := metrics.StopWatch(fmt.Sprintf("validator_%s_partial_duration", metrics.FilterMetricName(v.ChainID)))
	//defer stopWatch()

	// Initialize the flags all to TxValidationCode_NOT_VALIDATED
	protoutil.InitBlockMetadata(block)
	block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER] = txflags.New(len(block.Data.Data))

	txFlags, numValidated, _, err := v.validate(ctx, block, v.validationPolicy.GetTxFilter(block))
	if err != nil {
		// Error while validating. Don't send the result over Gossip - in this case the committer will
		// revalidate the unvalidated transactions.

		if err == context.Canceled {
			logger.Infof("[%s] ... validation of block %d was cancelled", v.channelID, block.Header.Number)

			return nil, err
		}

		logger.Infof("[%s] Got error in validation of block %d: %s", v.channelID, block.Header.Number, err)

		return nil, err
	}

	logger.Infof("[%s] ... finished validating %d transactions in block %d. Error: %v", v.channelID, numValidated, block.Header.Number, err)

	return txFlags, nil
}

func (v *validator) SubmitValidationResults(results *validationpolicy.ValidationResults) {
	logger.Debugf("[%s] Got validation results from %s for block %d", v.channelID, results.Endpoint, results.BlockNumber)

	v.resultsChan <- results
}

func (v *validator) validate(ctx context.Context, block *common.Block, shouldValidate validationpolicy.TxFilter) (txflags.ValidationFlags, int, []string, error) {
	var err error
	var errPos int

	// Initialize trans as valid here, then set invalidation reason code upon invalidation below
	txsfltr := txflags.New(len(block.Data.Data))

	results := make(chan *validatorv20.BlockValidationResult)

	blockFltr := txflags.ValidationFlags(block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER])
	transactions := make(map[int]struct{})
	for tIdx := range block.Data.Data {
		if !shouldValidate(tIdx) {
			continue
		}
		txStatus := blockFltr.Flag(tIdx)
		if txStatus != peer.TxValidationCode_NOT_VALIDATED {
			logger.Debugf("[%s] Not validating TxIdx[%d] in block %d since it has already been set to %s", v.channelID, tIdx, block.Header.Number, txStatus)

			continue
		}
		transactions[tIdx] = struct{}{}
	}

	txidArray := make([]string, len(block.Data.Data))

	go func() {
		n := 0

		for tIdx, d := range block.Data.Data {
			_, ok := transactions[tIdx]
			if !ok {
				continue
			}

			// ensure that we don't have too many concurrent validation workers
			if err := v.Semaphore.Acquire(ctx); err != nil {
				// Probably cancelled
				logger.Debugf("Unable to acquire semaphore after submitting %d of %d validation requests for block %d: %s", n, len(transactions), block.Header.Number, err)

				// Send error responses for the remaining transactions
				for ; n < len(transactions); n++ {
					results <- &validatorv20.BlockValidationResult{Err: err}
				}

				return
			}

			n++

			go func(index int, data []byte) {
				defer v.Semaphore.Release()

				v.ValidateTx(&validatorv20.BlockValidationRequest{
					D:     data,
					Block: block,
					TIdx:  index,
				}, results)
			}(tIdx, d)
		}
	}()

	logger.Debugf("expecting %d block validation responses", len(transactions))

	// now we read responses in the order in which they come back
	for i := 0; i < len(transactions); i++ {
		res := <-results

		if res.Err != nil {
			// if there is an error, we buffer its value, wait for
			// all workers to complete validation and then return
			// the error from the first tx in this block that returned an error
			logger.Debugf("got terminal error %s for idx %d", res.Err, res.TIdx)

			if err == nil || res.TIdx < errPos {
				err = res.Err
				errPos = res.TIdx

				if err == context.Canceled {
					logger.Debugf("Validation of block %d was canceled", block.Header.Number)
				} else {
					logger.Warningf("Got error %s for idx %d", err, res.TIdx)
				}
			}
		} else {
			// if there was no error, we set the txsfltr and we set the
			// txsChaincodeNames and txsUpgradedChaincodes maps
			logger.Debugf("got result for idx %d, code %d", res.TIdx, res.ValidationCode)

			txsfltr.SetFlag(res.TIdx, res.ValidationCode)

			if res.ValidationCode == peer.TxValidationCode_VALID {
				txidArray[res.TIdx] = res.Txid
			}
		}
	}

	return txsfltr, len(transactions), txidArray, err
}

func (v *validator) validateLocal(block *common.Block) {
	logger.Debugf("[%s] This committer is also a validator. Starting validation of transactions in block %d", v.channelID, block.Header.Number)

	txFlags, numTxns, _, err := v.validate(context.Background(), block, v.validationPolicy.GetTxFilter(block))
	if err != nil {
		if err == context.Canceled {
			logger.Infof("[%s] ... validation of block %d was cancelled", v.channelID, block.Header.Number)

			return
		}

		logger.Infof("[%s] Got error validating transactions in block %d: %s", v.channelID, block.Header.Number, err)

		return
	}

	logger.Infof("[%s] ... finished validating %d transactions in block %d", v.channelID, numTxns, block.Header.Number)

	v.resultsChan <- &validationpolicy.ValidationResults{
		BlockNumber: block.Header.Number,
		TxFlags:     txFlags,
		Err:         err,
		Local:       true,
		Endpoint:    v.Self().Endpoint,
		MSPID:       v.Self().MSPID,
		//TxIDs:       txIDs, // FIXME: Should we send back the transaction IDs so that we can check for duplicate IDs?
	}
}

func (v *validator) validateRemaining(ctx context.Context, block *common.Block, notValidated map[int]struct{}) {
	logger.Debugf("[%s] Starting validation of %d of %d transactions in block %d that were not validated ...", v.channelID, len(notValidated), len(block.Data.Data), block.Header.Number)

	txFlags, numValidated, _, err := v.validate(ctx, block,
		func(txIdx int) bool {
			_, ok := notValidated[txIdx]
			return ok
		},
	)

	if err == context.Canceled {
		logger.Infof("[%s] ... validation of %d of %d transactions in block %d that were not validated was cancelled", v.channelID, numValidated, len(block.Data.Data), block.Header.Number)

		return
	}

	logger.Infof("[%s] ... finished validating %d of %d transactions in block %d that were not validated. Err: %v", v.channelID, numValidated, len(block.Data.Data), block.Header.Number, err)

	self := v.Self()

	v.resultsChan <- &validationpolicy.ValidationResults{
		BlockNumber: block.Header.Number,
		TxFlags:     txFlags,
		Err:         err,
		Local:       true,
		Endpoint:    self.Endpoint,
		MSPID:       self.MSPID,
	}
}

func (v *validator) waitForValidationResults(cancel context.CancelFunc, blockNumber uint64, flags *txFlags, timeout time.Duration) error {
	logger.Infof("[%s] Waiting up to %s for validation responses for block %d ...", v.channelID, timeout, blockNumber)

	start := time.Now()
	timeoutChan := time.After(timeout)

	// See if there are cached results for the current block
	results := v.resultsCache.Remove(blockNumber)
	if len(results) > 0 {
		go func() {
			for _, result := range results {
				logger.Debugf("[%s] Retrieved validation results from the cache: %s", v.channelID, result)
				v.resultsChan <- result
			}
		}()
	}

	for {
		select {
		case result := <-v.resultsChan:
			logger.Infof("[%s] Got results from [%s] for block %d after %s", v.channelID, result.Endpoint, result.BlockNumber, time.Since(start))

			done, err := v.handleResults(blockNumber, flags, result)
			if err != nil {
				logger.Infof("[%s] Received error in validation results from [%s] peer for block %d: %s", v.channelID, result.Endpoint, result.BlockNumber, err)
				return err
			}

			if done {
				// CancelContextForBlock any background validations
				cancel()

				logger.Infof("[%s] Block %d is all validated. Done waiting %s for responses.", v.channelID, blockNumber, time.Since(start))
				return nil
			}
		case <-timeoutChan:
			logger.Infof("[%s] Timed out after %s waiting for validation response for block %d", v.channelID, timeout, blockNumber)
			return nil
		}
	}
}

func (v *validator) handleResults(blockNumber uint64, flags *txFlags, result *validationpolicy.ValidationResults) (done bool, err error) {
	if result.BlockNumber < blockNumber {
		logger.Debugf("[%s] Discarding validation results from [%s] for block %d since we're waiting on block %d", v.channelID, result.Endpoint, result.BlockNumber, blockNumber)
		return false, nil
	}

	if result.BlockNumber > blockNumber {
		// With cross-org validation this may be possible if we are lagging behind other orgs. In this case, cache the results and use them when we get to the block.
		logger.Debugf("[%s] Got validation results from [%s] for block %d but we're waiting on block %d. Caching the results.", v.channelID, result.Endpoint, result.BlockNumber, blockNumber)

		v.resultsCache.Add(result)
		return false, nil
	}

	if result.Err != nil {
		if result.Err == context.Canceled {
			// Ignore this error
			logger.Debugf("[%s] Validation was canceled in [%s] peer for block %d", v.channelID, result.Endpoint, result.BlockNumber)

			return false, nil
		}
		return true, result.Err
	}

	results := v.resultsCache.Add(result)
	err = v.validationPolicy.Validate(results)
	if err != nil {
		logger.Debugf("[%s] Validation policy NOT satisfied for block %d, Results: %s, Error: %s", v.channelID, result.BlockNumber, results, err)

		return false, nil
	}

	done = flags.merge(result.TxFlags)

	logger.Debugf("[%s] Validation policy satisfied for block %d, Results: %s, Done: %t", v.channelID, result.BlockNumber, results, done)

	return done, nil
}

func markTXIdDuplicates(txids []string, txsfltr txflags.ValidationFlags) {
	txidMap := make(map[string]struct{})

	for id, txid := range txids {
		if txid == "" {
			continue
		}

		_, in := txidMap[txid]
		if in {
			logger.Error("Duplicate txid", txid, "found, skipping")
			txsfltr.SetFlag(id, peer.TxValidationCode_DUPLICATE_TXID)
		} else {
			txidMap[txid] = struct{}{}
		}
	}
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cdbblkstorage

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/common/ledger/blkstorage"
	couchdb "github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/statedb/statecouchdb"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	"github.com/trustbloc/fabric-peer-ext/pkg/common/txflags"
)

const (
	preResetHeightKey = "preResetHeight"
	heightField       = "height"
)

// block document
const (
	idField             = "_id"
	blockHashField      = "hash"
	blockTxnsField      = "transactions"
	blockTxnIDField     = "id"
	blockHashIndexName  = "by_hash"
	blockHashIndexDoc   = "indexHash"
	blockAttachmentName = "block"
	blockKeyPrefix      = ""
	blockHeaderField    = "header"
	deletedField        = "_deleted"
)

// txn document
const (
	txnBlockNumberField   = "block_number"
	txnBlockHashField     = "block_hash"
	txnAttachmentName     = "transaction"
	txnValidationCode     = "validation_code"
	txnValidationCodeBase = 16
)

// checkpoint document
const (
	cpiAttachmentName        = "checkpointinfo"
	cpiAttachmentContentType = "application/octet-stream"
)

const blockHashIndexDef = `
	{
		"index": {
			"fields": ["` + blockHeaderField + `.` + blockHashField + `"]
		},
		"name": "` + blockHashIndexName + `",
		"ddoc": "` + blockHashIndexDoc + `",
		"type": "json"
	}`

type jsonValue map[string]interface{}

func (v jsonValue) toBytes() ([]byte, error) {
	return json.Marshal(v)
}

func blockToCouchDoc(block *common.Block) (*couchdb.CouchDoc, error) {
	jsonMap := make(jsonValue)

	blockHeader := block.GetHeader()

	key := blockNumberToKey(blockHeader.GetNumber())
	blockHashHex := hex.EncodeToString(protoutil.BlockHeaderHash(blockHeader))
	blockTxns, err := blockToTransactionsField(block)
	if err != nil {
		return nil, err
	}

	jsonMap[idField] = key
	header := make(jsonValue)
	header[blockHashField] = blockHashHex
	jsonMap[blockHeaderField] = header
	jsonMap[blockTxnsField] = blockTxns

	jsonBytes, err := jsonMap.toBytes()
	if err != nil {
		return nil, err
	}
	couchDoc := &couchdb.CouchDoc{JSONValue: jsonBytes}

	attachment, err := blockToAttachment(block)
	if err != nil {
		return nil, err
	}

	attachments := append([]*couchdb.AttachmentInfo{}, attachment)
	couchDoc.Attachments = attachments
	return couchDoc, nil
}

func blockToTxnCouchDocs(block *common.Block, attachTxn bool) ([]*couchdb.CouchDoc, error) {
	blockHeader := block.GetHeader()
	blockNumber := blockNumberToKey(blockHeader.GetNumber())
	blockHash := hex.EncodeToString(protoutil.BlockHeaderHash(blockHeader))

	blockData := block.GetData()

	blockMetadata := block.GetMetadata()
	txValidationFlags := txflags.ValidationFlags(blockMetadata.GetMetadata()[common.BlockMetadataIndex_TRANSACTIONS_FILTER])

	txnDocs := make([]*couchdb.CouchDoc, 0)

	for i, txEnvelopeBytes := range blockData.GetData() {
		envelope, err := protoutil.GetEnvelopeFromBlock(txEnvelopeBytes)
		if err != nil {
			return nil, err
		}

		txnDoc, err := blockTxnToCouchDoc(blockNumber, blockHash, envelope, txValidationFlags.Flag(i), attachTxn)
		if err == errorNoTxID {
			continue
		} else if err != nil {
			return nil, err
		}

		txnDocs = append(txnDocs, txnDoc)
	}

	return txnDocs, nil
}

var errorNoTxID = errors.New("missing transaction ID")

func blockTxnToCouchDoc(blockNumber string, blockHash string, txEnvelope *common.Envelope, validationCode peer.TxValidationCode, attachTxn bool) (*couchdb.CouchDoc, error) {
	txID, err := extractTxIDFromEnvelope(txEnvelope)
	if err != nil {
		return nil, errors.WithMessage(err, "transaction ID could not be extracted")
	}

	// TODO: is the empty transaction queryable? If so, need to change this to a default transaction ID.
	if txID == "" {
		return nil, errorNoTxID
	}

	jsonMap := make(jsonValue)
	jsonMap[idField] = txID
	jsonMap[txnBlockHashField] = blockHash
	jsonMap[txnBlockNumberField] = blockNumber
	jsonMap[txnValidationCode] = strconv.FormatInt(int64(validationCode), txnValidationCodeBase)

	jsonBytes, err := jsonMap.toBytes()
	if err != nil {
		return nil, err
	}
	couchDoc := &couchdb.CouchDoc{JSONValue: jsonBytes}

	if attachTxn {
		attachment, err := txnEnvelopeToAttachment(txEnvelope)
		if err != nil {
			return nil, err
		}

		attachments := append([]*couchdb.AttachmentInfo{}, attachment)
		couchDoc.Attachments = attachments
	}
	return couchDoc, nil
}

func checkpointInfoToCouchDoc(i *checkpointInfo) (*couchdb.CouchDoc, error) {
	jsonMap := make(jsonValue)

	jsonMap[idField] = blkMgrInfoKey

	jsonBytes, err := jsonMap.toBytes()
	if err != nil {
		return nil, err
	}
	couchDoc := &couchdb.CouchDoc{JSONValue: jsonBytes}

	attachment, err := checkpointInfoToAttachment(i)
	if err != nil {
		return nil, err
	}

	attachments := append([]*couchdb.AttachmentInfo{}, attachment)
	couchDoc.Attachments = attachments
	return couchDoc, nil
}

func preResetHeightKeyToCouchDoc(blockNumber string) (*couchdb.CouchDoc, error) {
	jsonMap := make(jsonValue)

	jsonMap[idField] = preResetHeightKey
	jsonMap[heightField] = blockNumber

	jsonBytes, err := jsonMap.toBytes()
	if err != nil {
		return nil, err
	}
	couchDoc := &couchdb.CouchDoc{JSONValue: jsonBytes}

	return couchDoc, nil
}

func checkpointInfoToAttachment(i *checkpointInfo) (*couchdb.AttachmentInfo, error) {
	checkpointInfoBytes, err := i.marshal()
	if err != nil {
		return nil, errors.Wrapf(err, "marshaling checkpointInfo failed")
	}

	attachment := &couchdb.AttachmentInfo{}
	attachment.AttachmentBytes = checkpointInfoBytes
	attachment.ContentType = cpiAttachmentContentType
	attachment.Name = cpiAttachmentName

	return attachment, nil
}

func blockToTransactionsField(block *common.Block) ([]jsonValue, error) {
	blockData := block.GetData()

	var txns []jsonValue

	for _, txEnvelopeBytes := range blockData.GetData() {
		envelope, err := protoutil.GetEnvelopeFromBlock(txEnvelopeBytes)
		if err != nil {
			return nil, err
		}

		txID, err := extractTxIDFromEnvelope(envelope)
		if err != nil {
			return nil, errors.WithMessage(err, "transaction ID could not be extracted")
		}

		txField := make(jsonValue)
		txField[blockTxnIDField] = txID

		txns = append(txns, txField)
	}

	return txns, nil
}

func txnEnvelopeToAttachment(txEnvelope *common.Envelope) (*couchdb.AttachmentInfo, error) {
	txEnvelopeBytes, err := proto.Marshal(txEnvelope)
	if err != nil {
		return nil, errors.Wrapf(err, "marshaling block failed")
	}

	attachment := &couchdb.AttachmentInfo{}
	attachment.AttachmentBytes = txEnvelopeBytes
	attachment.ContentType = cpiAttachmentContentType
	attachment.Name = txnAttachmentName

	return attachment, nil
}

func blockToAttachment(block *common.Block) (*couchdb.AttachmentInfo, error) {
	blockBytes, err := proto.Marshal(block)
	if err != nil {
		return nil, errors.Wrapf(err, "marshaling block failed")
	}

	attachment := &couchdb.AttachmentInfo{}
	attachment.AttachmentBytes = blockBytes
	attachment.ContentType = cpiAttachmentContentType
	attachment.Name = blockAttachmentName

	return attachment, nil
}

func couchDocToBlock(doc *couchdb.CouchDoc) (*common.Block, error) {
	return couchAttachmentsToBlock(doc.Attachments)
}

func couchAttachmentsToBlock(attachments []*couchdb.AttachmentInfo) (*common.Block, error) {
	var blockBytes []byte
	block := common.Block{}

	// get binary data from attachment
	for _, a := range attachments {
		if a.Name == blockAttachmentName {
			blockBytes = a.AttachmentBytes
		}
	}

	if len(blockBytes) == 0 {
		return nil, errors.New("block is not within couchDB document")
	}

	err := proto.Unmarshal(blockBytes, &block)
	if err != nil {
		return nil, errors.Wrapf(err, "block from couchDB document could not be unmarshaled")
	}

	return &block, nil
}

func couchAttachmentsToTxnEnvelope(attachments []*couchdb.AttachmentInfo) (*common.Envelope, error) {
	var envelope common.Envelope
	var txnBytes []byte

	// get binary data from attachment
	for _, a := range attachments {
		if a.Name == txnAttachmentName {
			txnBytes = a.AttachmentBytes
		}
	}

	if len(txnBytes) == 0 {
		return nil, errors.New("transaction envelope is not within couchDB document")
	}

	err := proto.Unmarshal(txnBytes, &envelope)
	if err != nil {
		return nil, errors.Wrapf(err, "transaction from couchDB document could not be unmarshaled")
	}

	return &envelope, nil
}

func couchDocToCheckpointInfo(doc *couchdb.CouchDoc) (*checkpointInfo, error) {
	return couchAttachmentsToCheckpointInfo(doc.Attachments)
}

func couchAttachmentsToCheckpointInfo(attachments []*couchdb.AttachmentInfo) (*checkpointInfo, error) {
	var checkpointInfoBytes []byte
	cpInfo := checkpointInfo{}
	// get binary data from attachment
	for _, a := range attachments {
		if a.Name == cpiAttachmentName {
			checkpointInfoBytes = a.AttachmentBytes
		}
	}
	if len(checkpointInfoBytes) == 0 {
		return nil, errors.New("checkpointInfo is not within couchDB document")
	}
	err := cpInfo.unmarshal(checkpointInfoBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "checkpointInfo from couchDB document could not be unmarshaled")
	}
	return &cpInfo, nil
}

func blockNumberToKey(blockNum uint64) string {
	return blockKeyPrefix + strconv.FormatUint(blockNum, 10)
}

func retrieveBlockQuery(db couchDB, query string) (*common.Block, error) {
	results, _, err := db.QueryDocuments(query)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, blkstorage.ErrNotFoundInIndex
	}

	if len(results[0].Attachments) == 0 {
		return nil, errors.New("block bytes not found")
	}

	return couchAttachmentsToBlock(results[0].Attachments)
}

func retrieveJSONQuery(db couchDB, id string) (jsonValue, error) {
	doc, _, err := db.ReadDoc(id)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, blkstorage.ErrNotFoundInIndex
	}

	return couchDocToJSON(doc)
}

func couchDocToJSON(doc *couchdb.CouchDoc) (jsonValue, error) {
	// create a generic map unmarshal the json
	jsonResult := make(map[string]interface{})
	decoder := json.NewDecoder(bytes.NewBuffer(doc.JSONValue))
	decoder.UseNumber()

	err := decoder.Decode(&jsonResult)
	if err != nil {
		return nil, errors.Wrapf(err, "result from DB is not JSON encoded")
	}

	return jsonResult, nil
}

func addDeletedFlagToCouchDoc(value []byte) (*couchdb.CouchDoc, error) {
	// create a generic map unmarshal the json
	jsonResult := make(map[string]interface{})
	decoder := json.NewDecoder(bytes.NewBuffer(value))
	decoder.UseNumber()

	err := decoder.Decode(&jsonResult)
	if err != nil {
		return nil, errors.Wrapf(err, "result from DB is not JSON encoded")
	}

	jsonResult[deletedField] = true

	valueBytes, err := json.Marshal(jsonResult)
	if err != nil {
		return nil, err
	}

	couchDoc := &couchdb.CouchDoc{JSONValue: valueBytes}

	return couchDoc, nil
}

func readDocRange(db *couchdb.CouchDatabase, startKey, endKey string, queryLimit int32) ([]*couchdb.QueryResult, error) {
	var finalResults []*couchdb.QueryResult
	var finalNextStartKey string

	if queryLimit <= 0 {
		queryLimit = 1
	}

	for {
		results, nextStartKey, err := db.ReadDocRange(startKey, endKey, queryLimit)
		if err != nil {
			logger.Debugf("Error calling ReadDocRange(): %s\n", err.Error())
			return nil, err
		}

		var filteredResults []*couchdb.QueryResult
		for _, doc := range results {
			if !isCouchInternalKey(doc.ID) {
				filteredResults = append(filteredResults, doc)
			}
		}

		finalResults = append(finalResults, filteredResults...)
		finalNextStartKey = nextStartKey
		if finalNextStartKey == "" || finalNextStartKey == endKey {
			break
		}
		startKey = finalNextStartKey
	}

	return finalResults, nil
}

func isCouchInternalKey(key string) bool {
	return len(key) != 0 && key[0] == '_'
}

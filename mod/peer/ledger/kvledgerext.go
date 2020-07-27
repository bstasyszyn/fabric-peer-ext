/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ledger

import (
	"github.com/hyperledger/fabric-protos-go/common"

	xledgerapi "github.com/hyperledger/fabric/extensions/ledger/api"
)

//NewKVLedgerExtension returns peer ledger extension implementation using block store provided
func NewKVLedgerExtension(store xledgerapi.BlockStore) xledgerapi.PeerLedgerExtension {
	return &kvLedger{store}
}

//kvLedger is implementation of Peer Ledger extension
type kvLedger struct {
	blockStore xledgerapi.BlockStore
}

// CheckpointBlock updates checkpoint info of underlying blockstore with given block
func (l *kvLedger) CheckpointBlock(block *common.Block) error {
	return l.blockStore.CheckpointBlock(block)
}
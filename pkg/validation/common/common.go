/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"context"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy"

	"github.com/trustbloc/fabric-peer-ext/pkg/common/txflags"
)

type Validator interface {
	ValidatePartial(ctx context.Context, block *cb.Block) (txflags.ValidationFlags, error)
	SubmitValidationResults(results *validationpolicy.ValidationResults)
	GetValidatingPeers(block *cb.Block) ([]*discovery.Member, error)
}

type ValidationRequest struct {
	// Block is the block to validate
	Block *cb.Block

	// BlockBytes is an optional, marshalled protobuf of the block that
	// (if present) will be used in the Gossip request. If nil then the block
	// will be marshalled before being sent.
	BlockBytes []byte
}

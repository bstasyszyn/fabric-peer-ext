/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/trustbloc/fabric-peer-ext/pkg/common/txflags"
)

type Validator interface {
	Validate(block *cb.Block) (txflags.ValidationFlags, error)
}

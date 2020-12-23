/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	db "github.com/hyperledger/fabric-protos-go/discovery"
)

type ValidationDescriptor struct {
	ValidatorsByGroups map[string]*db.Peers
	Layouts            []*db.Layout
}

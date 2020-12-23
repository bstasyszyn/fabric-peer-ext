/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package state

import (
	vcommon "github.com/trustbloc/fabric-peer-ext/pkg/validation/common"
)

var vmInstance = &ValidationMgr{}

type validationProvider interface {
	SendValidationRequest(channelID string, req *vcommon.ValidationRequest)
	ValidatePending(channelID string, blockNum uint64)
}

type contextProvider interface {
	CancelContextForBlock(channelID string, blockNum uint64)
}

type ValidationMgr struct {
	vp validationProvider
	cp contextProvider
}

func InitValidationMgr(vp validationProvider, cp contextProvider) *ValidationMgr {
	logger.Info("Initializing validation manager")

	vmInstance.vp = vp
	vmInstance.cp = cp

	return vmInstance
}

func (m *ValidationMgr) sendValidateRequest(channelID string, req *vcommon.ValidationRequest) {
	m.vp.SendValidationRequest(channelID, req)
}

func (m *ValidationMgr) validatePending(channelID string, blockNum uint64) {
	m.vp.ValidatePending(channelID, blockNum)
}

func (m *ValidationMgr) cancelValidation(channelID string, blockNum uint64) {
	m.cp.CancelContextForBlock(channelID, blockNum)
}

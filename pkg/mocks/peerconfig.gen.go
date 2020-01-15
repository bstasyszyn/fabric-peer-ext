// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/trustbloc/fabric-peer-ext/pkg/txn/api"
)

type PeerConfig struct {
	PeerIDStub        func() string
	peerIDMutex       sync.RWMutex
	peerIDArgsForCall []struct{}
	peerIDReturns     struct {
		result1 string
	}
	peerIDReturnsOnCall map[int]struct {
		result1 string
	}
	MSPIDStub        func() string
	mSPIDMutex       sync.RWMutex
	mSPIDArgsForCall []struct{}
	mSPIDReturns     struct {
		result1 string
	}
	mSPIDReturnsOnCall map[int]struct {
		result1 string
	}
	PeerAddressStub        func() string
	peerAddressMutex       sync.RWMutex
	peerAddressArgsForCall []struct{}
	peerAddressReturns     struct {
		result1 string
	}
	peerAddressReturnsOnCall map[int]struct {
		result1 string
	}
	MSPConfigPathStub        func() string
	mSPConfigPathMutex       sync.RWMutex
	mSPConfigPathArgsForCall []struct{}
	mSPConfigPathReturns     struct {
		result1 string
	}
	mSPConfigPathReturnsOnCall map[int]struct {
		result1 string
	}
	TLSCertPathStub        func() string
	tLSCertPathMutex       sync.RWMutex
	tLSCertPathArgsForCall []struct{}
	tLSCertPathReturns     struct {
		result1 string
	}
	tLSCertPathReturnsOnCall map[int]struct {
		result1 string
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *PeerConfig) PeerID() string {
	fake.peerIDMutex.Lock()
	ret, specificReturn := fake.peerIDReturnsOnCall[len(fake.peerIDArgsForCall)]
	fake.peerIDArgsForCall = append(fake.peerIDArgsForCall, struct{}{})
	fake.recordInvocation("PeerID", []interface{}{})
	fake.peerIDMutex.Unlock()
	if fake.PeerIDStub != nil {
		return fake.PeerIDStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.peerIDReturns.result1
}

func (fake *PeerConfig) PeerIDCallCount() int {
	fake.peerIDMutex.RLock()
	defer fake.peerIDMutex.RUnlock()
	return len(fake.peerIDArgsForCall)
}

func (fake *PeerConfig) PeerIDReturns(result1 string) {
	fake.PeerIDStub = nil
	fake.peerIDReturns = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) PeerIDReturnsOnCall(i int, result1 string) {
	fake.PeerIDStub = nil
	if fake.peerIDReturnsOnCall == nil {
		fake.peerIDReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.peerIDReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) MSPID() string {
	fake.mSPIDMutex.Lock()
	ret, specificReturn := fake.mSPIDReturnsOnCall[len(fake.mSPIDArgsForCall)]
	fake.mSPIDArgsForCall = append(fake.mSPIDArgsForCall, struct{}{})
	fake.recordInvocation("MSPID", []interface{}{})
	fake.mSPIDMutex.Unlock()
	if fake.MSPIDStub != nil {
		return fake.MSPIDStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.mSPIDReturns.result1
}

func (fake *PeerConfig) MSPIDCallCount() int {
	fake.mSPIDMutex.RLock()
	defer fake.mSPIDMutex.RUnlock()
	return len(fake.mSPIDArgsForCall)
}

func (fake *PeerConfig) MSPIDReturns(result1 string) {
	fake.MSPIDStub = nil
	fake.mSPIDReturns = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) MSPIDReturnsOnCall(i int, result1 string) {
	fake.MSPIDStub = nil
	if fake.mSPIDReturnsOnCall == nil {
		fake.mSPIDReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.mSPIDReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) PeerAddress() string {
	fake.peerAddressMutex.Lock()
	ret, specificReturn := fake.peerAddressReturnsOnCall[len(fake.peerAddressArgsForCall)]
	fake.peerAddressArgsForCall = append(fake.peerAddressArgsForCall, struct{}{})
	fake.recordInvocation("PeerAddress", []interface{}{})
	fake.peerAddressMutex.Unlock()
	if fake.PeerAddressStub != nil {
		return fake.PeerAddressStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.peerAddressReturns.result1
}

func (fake *PeerConfig) PeerAddressCallCount() int {
	fake.peerAddressMutex.RLock()
	defer fake.peerAddressMutex.RUnlock()
	return len(fake.peerAddressArgsForCall)
}

func (fake *PeerConfig) PeerAddressReturns(result1 string) {
	fake.PeerAddressStub = nil
	fake.peerAddressReturns = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) PeerAddressReturnsOnCall(i int, result1 string) {
	fake.PeerAddressStub = nil
	if fake.peerAddressReturnsOnCall == nil {
		fake.peerAddressReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.peerAddressReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) MSPConfigPath() string {
	fake.mSPConfigPathMutex.Lock()
	ret, specificReturn := fake.mSPConfigPathReturnsOnCall[len(fake.mSPConfigPathArgsForCall)]
	fake.mSPConfigPathArgsForCall = append(fake.mSPConfigPathArgsForCall, struct{}{})
	fake.recordInvocation("MSPConfigPath", []interface{}{})
	fake.mSPConfigPathMutex.Unlock()
	if fake.MSPConfigPathStub != nil {
		return fake.MSPConfigPathStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.mSPConfigPathReturns.result1
}

func (fake *PeerConfig) MSPConfigPathCallCount() int {
	fake.mSPConfigPathMutex.RLock()
	defer fake.mSPConfigPathMutex.RUnlock()
	return len(fake.mSPConfigPathArgsForCall)
}

func (fake *PeerConfig) MSPConfigPathReturns(result1 string) {
	fake.MSPConfigPathStub = nil
	fake.mSPConfigPathReturns = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) MSPConfigPathReturnsOnCall(i int, result1 string) {
	fake.MSPConfigPathStub = nil
	if fake.mSPConfigPathReturnsOnCall == nil {
		fake.mSPConfigPathReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.mSPConfigPathReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) TLSCertPath() string {
	fake.tLSCertPathMutex.Lock()
	ret, specificReturn := fake.tLSCertPathReturnsOnCall[len(fake.tLSCertPathArgsForCall)]
	fake.tLSCertPathArgsForCall = append(fake.tLSCertPathArgsForCall, struct{}{})
	fake.recordInvocation("TLSCertPath", []interface{}{})
	fake.tLSCertPathMutex.Unlock()
	if fake.TLSCertPathStub != nil {
		return fake.TLSCertPathStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.tLSCertPathReturns.result1
}

func (fake *PeerConfig) TLSCertPathCallCount() int {
	fake.tLSCertPathMutex.RLock()
	defer fake.tLSCertPathMutex.RUnlock()
	return len(fake.tLSCertPathArgsForCall)
}

func (fake *PeerConfig) TLSCertPathReturns(result1 string) {
	fake.TLSCertPathStub = nil
	fake.tLSCertPathReturns = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) TLSCertPathReturnsOnCall(i int, result1 string) {
	fake.TLSCertPathStub = nil
	if fake.tLSCertPathReturnsOnCall == nil {
		fake.tLSCertPathReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.tLSCertPathReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *PeerConfig) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.peerIDMutex.RLock()
	defer fake.peerIDMutex.RUnlock()
	fake.mSPIDMutex.RLock()
	defer fake.mSPIDMutex.RUnlock()
	fake.peerAddressMutex.RLock()
	defer fake.peerAddressMutex.RUnlock()
	fake.mSPConfigPathMutex.RLock()
	defer fake.mSPConfigPathMutex.RUnlock()
	fake.tLSCertPathMutex.RLock()
	defer fake.tLSCertPathMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *PeerConfig) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ api.PeerConfig = new(PeerConfig)
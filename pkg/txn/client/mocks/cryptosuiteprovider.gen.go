// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
)

type CryptoSuiteProvider struct {
	CryptoSuiteStub        func() core.CryptoSuite
	cryptoSuiteMutex       sync.RWMutex
	cryptoSuiteArgsForCall []struct{}
	cryptoSuiteReturns     struct {
		result1 core.CryptoSuite
	}
	cryptoSuiteReturnsOnCall map[int]struct {
		result1 core.CryptoSuite
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *CryptoSuiteProvider) CryptoSuite() core.CryptoSuite {
	fake.cryptoSuiteMutex.Lock()
	ret, specificReturn := fake.cryptoSuiteReturnsOnCall[len(fake.cryptoSuiteArgsForCall)]
	fake.cryptoSuiteArgsForCall = append(fake.cryptoSuiteArgsForCall, struct{}{})
	fake.recordInvocation("CryptoSuite", []interface{}{})
	fake.cryptoSuiteMutex.Unlock()
	if fake.CryptoSuiteStub != nil {
		return fake.CryptoSuiteStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.cryptoSuiteReturns.result1
}

func (fake *CryptoSuiteProvider) CryptoSuiteCallCount() int {
	fake.cryptoSuiteMutex.RLock()
	defer fake.cryptoSuiteMutex.RUnlock()
	return len(fake.cryptoSuiteArgsForCall)
}

func (fake *CryptoSuiteProvider) CryptoSuiteReturns(result1 core.CryptoSuite) {
	fake.CryptoSuiteStub = nil
	fake.cryptoSuiteReturns = struct {
		result1 core.CryptoSuite
	}{result1}
}

func (fake *CryptoSuiteProvider) CryptoSuiteReturnsOnCall(i int, result1 core.CryptoSuite) {
	fake.CryptoSuiteStub = nil
	if fake.cryptoSuiteReturnsOnCall == nil {
		fake.cryptoSuiteReturnsOnCall = make(map[int]struct {
			result1 core.CryptoSuite
		})
	}
	fake.cryptoSuiteReturnsOnCall[i] = struct {
		result1 core.CryptoSuite
	}{result1}
}

func (fake *CryptoSuiteProvider) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.cryptoSuiteMutex.RLock()
	defer fake.cryptoSuiteMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *CryptoSuiteProvider) recordInvocation(key string, args []interface{}) {
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
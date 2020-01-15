/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

// UpdateHandler handles updates/deletes of config keys
type UpdateHandler func(kv *KeyValue)

// Service defines the operations of a configuration service
type Service interface {
	Get(key *Key) (*Value, error)
	Query(criteria *Criteria) ([]*KeyValue, error)
	AddUpdateHandler(handler UpdateHandler)
}

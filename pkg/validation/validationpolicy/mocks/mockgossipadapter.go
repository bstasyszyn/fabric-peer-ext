/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	gossipproto "github.com/hyperledger/fabric-protos-go/gossip"
	gossipapi "github.com/hyperledger/fabric/gossip/api"
	"github.com/hyperledger/fabric/gossip/comm"
	"github.com/hyperledger/fabric/gossip/common"
	"github.com/hyperledger/fabric/gossip/discovery"
)

type MessageHandler func(msg *gossipproto.GossipMessage)

type MockGossipAdapter struct {
	self        discovery.NetworkMember
	members     []discovery.NetworkMember
	identitySet gossipapi.PeerIdentitySet
	handler     MessageHandler
}

func NewMockGossipAdapter() *MockGossipAdapter {
	return &MockGossipAdapter{}
}

func (m *MockGossipAdapter) Self(mspID string, self discovery.NetworkMember) *MockGossipAdapter {
	m.self = self
	m.identitySet = append(m.identitySet, gossipapi.PeerIdentityInfo{
		PKIId:        self.PKIid,
		Organization: []byte(mspID),
	})
	return m
}

func (m *MockGossipAdapter) Member(mspID string, member discovery.NetworkMember) *MockGossipAdapter {
	m.members = append(m.members, member)
	m.identitySet = append(m.identitySet, gossipapi.PeerIdentityInfo{
		PKIId:        member.PKIid,
		Organization: []byte(mspID),
	})
	return m
}

func (m *MockGossipAdapter) MessageHandler(handler MessageHandler) *MockGossipAdapter {
	m.handler = handler
	return m
}

func (m *MockGossipAdapter) PeersOfChannel(id common.ChannelID) []discovery.NetworkMember {
	return m.members
}

func (m *MockGossipAdapter) SelfMembershipInfo() discovery.NetworkMember {
	return m.self
}

func (m *MockGossipAdapter) IdentityInfo() gossipapi.PeerIdentitySet {
	return m.identitySet
}

// Send sends a message to remote peers
func (m *MockGossipAdapter) Send(msg *gossipproto.GossipMessage, peers ...*comm.RemotePeer) {
	if m.handler != nil {
		go m.handler(msg)
	}
}

func NewMember(endpoint string, pkiID []byte, roles ...string) discovery.NetworkMember {
	return discovery.NetworkMember{
		Endpoint: endpoint,
		PKIid:    pkiID,
		Properties: &gossipproto.Properties{
			Roles: roles,
		},
	}
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/discovery"
	"github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/gossip/common"

	"github.com/trustbloc/fabric-peer-ext/pkg/roles"
	cvp "github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy/common"
)

type MockValidatorDiscovery struct {
	err  error
	desc *cvp.ValidationDescriptor
}

func NewMockValidatorDiscovery() *MockValidatorDiscovery {
	return &MockValidatorDiscovery{
		desc: &cvp.ValidationDescriptor{
			ValidatorsByGroups: make(map[string]*discovery.Peers),
		},
	}
}

func (m *MockValidatorDiscovery) Error(err error) *MockValidatorDiscovery {
	m.err = err
	return m
}

func (m *MockValidatorDiscovery) Group(groupName string, peers ...*MockPeer) *MockValidatorDiscovery {
	m.desc.ValidatorsByGroups[groupName] = asDiscoveryPeers(peers)
	return m
}

func (m *MockValidatorDiscovery) Layout(groups ...string) *MockValidatorDiscovery {
	quantitiesByGroup := make(map[string]uint32)
	for _, grp := range groups {
		quantitiesByGroup[grp] = 1
	}
	m.desc.Layouts = append(m.desc.Layouts, &discovery.Layout{QuantitiesByGroup: quantitiesByGroup})
	return m
}

func (m *MockValidatorDiscovery) PeersForValidation(chainID common.ChannelID, policy policies.InquireablePolicy) (*cvp.ValidationDescriptor, error) {
	return m.desc, m.err
}

// MockPeer contains information about a Discover peer endpoint
type MockPeer struct {
	MSPID    string
	Endpoint string
	Roles    []string
}

func Peer(mspID, endpoint string, roles ...string) *MockPeer {
	return &MockPeer{
		MSPID:    mspID,
		Endpoint: endpoint,
		Roles:    roles,
	}
}

func asDiscoveryPeers(mockPeers []*MockPeer) *discovery.Peers {
	peers := &discovery.Peers{}
	for _, mp := range mockPeers {
		if roles.FromStrings(mp.Roles...).Contains(roles.ValidatorRole) {
			peers.Peers = append(peers.Peers, asDiscoveryPeer(mp))
		}
	}
	return peers
}

func asDiscoveryPeer(p *MockPeer) *discovery.Peer {
	memInfoMsg := &gossip.GossipMessage{
		Content: &gossip.GossipMessage_AliveMsg{
			AliveMsg: &gossip.AliveMessage{
				Membership: &gossip.Member{
					Endpoint: p.Endpoint,
				},
			},
		},
	}
	memInfoPayload, err := proto.Marshal(memInfoMsg)
	if err != nil {
		panic(err.Error())
	}

	stateInfoMsg := &gossip.GossipMessage{
		Content: &gossip.GossipMessage_StateInfo{
			StateInfo: &gossip.StateInfo{
				Properties: &gossip.Properties{
					Roles: p.Roles,
				},
			},
		},
	}
	stateInfoPayload, err := proto.Marshal(stateInfoMsg)
	if err != nil {
		panic(err.Error())
	}

	return &discovery.Peer{
		MembershipInfo: &gossip.Envelope{
			Payload: memInfoPayload,
		},
		StateInfo: &gossip.Envelope{
			Payload: stateInfoPayload,
		},
	}
}

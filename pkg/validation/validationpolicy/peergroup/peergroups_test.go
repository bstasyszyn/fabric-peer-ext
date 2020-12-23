/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peergroup

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
)

const (
	org1MSP = "org1MSP"

	p1Endpoint = "p1.org1.com"
	p2Endpoint = "p2.org1.com"
	p3Endpoint = "p3.org1.com"
	p4Endpoint = "p4.org1.com"
	p5Endpoint = "p5.org1.com"
	p6Endpoint = "p6.org1.com"
	p7Endpoint = "p7.org1.com"
)

var (
	p1 = NewMember(org1MSP, p1Endpoint)
	p2 = NewMember(org1MSP, p2Endpoint)
	p3 = NewMember(org1MSP, p3Endpoint)
	p4 = NewMember(org1MSP, p4Endpoint)
	p5 = NewMember(org1MSP, p5Endpoint)
	p6 = NewMember(org1MSP, p6Endpoint)
	p7 = NewMember(org1MSP, p7Endpoint)
)

func TestPeerGroupsSort(t *testing.T) {
	pg1 := discovery.PeerGroup{p2, p1, p3}
	pg2 := discovery.PeerGroup{p5, p4}
	pg3 := discovery.PeerGroup{p7, p6}

	pgs := PeerGroups{pg3, pg1, pg2}

	pgs.Sort()

	// The peer groups should be sorted
	assert.Equal(t, pg1, pgs[0])
	assert.Equal(t, pg2, pgs[1])
	assert.Equal(t, pg3, pgs[2])

	// Each peer group should be sorted
	assert.Equal(t, p1, pg1[0])
	assert.Equal(t, p2, pg1[1])
	assert.Equal(t, p3, pg1[2])

	assert.Equal(t, p4, pg2[0])
	assert.Equal(t, p5, pg2[1])

	assert.Equal(t, p6, pg3[0])
	assert.Equal(t, p7, pg3[1])
}

func TestPeerGroupsContains(t *testing.T) {
	pg1 := discovery.PeerGroup{p1, p2, p3}
	pg2 := discovery.PeerGroup{p3, p4, p5}
	pg3 := discovery.PeerGroup{p1, p4}
	pg4 := discovery.PeerGroup{p2, p5, p6}
	pg5 := discovery.PeerGroup{p6, p7}

	pgs1 := PeerGroups{pg1, pg2}

	assert.True(t, pgs1.Contains(p1))
	assert.True(t, pgs1.Contains(p2))
	assert.True(t, pgs1.Contains(p3))
	assert.True(t, pgs1.Contains(p4))
	assert.True(t, pgs1.Contains(p5))
	assert.False(t, pgs1.Contains(p6))

	assert.True(t, pgs1.ContainsAll(pg3))
	assert.False(t, pgs1.ContainsAll(pg4))
	assert.True(t, pgs1.ContainsAny(pg4))
	assert.False(t, pgs1.ContainsAny(pg5))
}

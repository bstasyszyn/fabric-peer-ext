/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peergroup

import (
	"sort"

	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
)

// PeerGroups is a set of peer groups
type PeerGroups []discovery.PeerGroup

func (g PeerGroups) String() string {
	s := "("
	for i, p := range g {
		s += p.String()
		if i+1 < len(g) {
			s += ", "
		}
	}
	s += ")"
	return s
}

// Sort sorts the peer group by endpoint
func (g PeerGroups) Sort() PeerGroups {
	// First sort each peer group
	for _, pg := range g {
		pg.Sort()
	}
	// Now sort the peer groups
	sort.Sort(g)

	return g
}

// Contains returns true if the given peer is contained within any of the peer groups
func (g PeerGroups) Contains(p *discovery.Member) bool {
	for _, pg := range g {
		if pg.Contains(p) {
			return true
		}
	}
	return false
}

// ContainsAll returns true if all of the peers within the given peer group are contained within the peer groups
func (g PeerGroups) ContainsAll(peerGroup discovery.PeerGroup) bool {
	for _, p := range peerGroup {
		if !g.Contains(p) {
			return false
		}
	}
	return true
}

// ContainsAny returns true if any of the peers within the given peer group are contained within the peer groups
func (g PeerGroups) ContainsAny(peerGroup discovery.PeerGroup) bool {
	for _, pg := range g {
		if pg.ContainsAny(peerGroup) {
			return true
		}
	}
	return false
}

func (g PeerGroups) Len() int {
	return len(g)
}

func (g PeerGroups) Less(i, j int) bool {
	return g[i].String() < g[j].String()
}

func (g PeerGroups) Swap(i, j int) {
	g[i], g[j] = g[j], g[i]
}

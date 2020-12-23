/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validationpolicy

import (
	"hash/fnv"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	db "github.com/hyperledger/fabric-protos-go/discovery"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/common/policies"
	gossipapi "github.com/hyperledger/fabric/extensions/gossip/api"
	"github.com/hyperledger/fabric/gossip/common"
	discimpl "github.com/hyperledger/fabric/gossip/discovery"
	gprotoext "github.com/hyperledger/fabric/gossip/protoext"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"

	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
	"github.com/trustbloc/fabric-peer-ext/pkg/roles"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy/peergroup"
)

type inquireablePolicy interface {
	policies.InquireablePolicy
	MaxGroups() int32
}

type ValidatorDiscovery interface {
	// FIXME: should be member *discimpl.NetworkMember
	PeersByPolicy(chainID common.ChannelID, policy policies.InquireablePolicy, filter func(member discimpl.NetworkMember) bool) (*gossipapi.PeerPolicyDescriptor, error)
}

type evaluator struct {
	*discovery.Discovery
	channelID          string
	policy             inquireablePolicy
	validator          policies.Policy
	orgValidator       policies.Policy
	validatorDiscovery ValidatorDiscovery
	localOrgPolicy     bool
}

func newEvaluator(channelID string, discovery *discovery.Discovery, validator, orgValidator policies.Policy,
	policy inquireablePolicy, validatorDiscovery ValidatorDiscovery, localOrgPolicy bool) (*evaluator, error) {
	return &evaluator{
		channelID:          channelID,
		policy:             policy,
		validator:          validator,
		orgValidator:       orgValidator,
		Discovery:          discovery,
		localOrgPolicy:     localOrgPolicy,
		validatorDiscovery: validatorDiscovery,
	}, nil
}

// FIXME: This algorithm should be modified so that there's a minimum number of transactions in a block in order that distributed
// validation kicks in, since, for a small set of transactions, there's more overhead in sending a validation request than there
// is for a single peer to validate. For example,
//
// Example 1:
//   Given:
//   - Peer0 = committer
//   - Peer1 = validator
//   - Peer2 = validator
//   - transactionThreshold=50
//   If:
//   - Block 1 has 40 txns: Peer group: [Peer1] (or [Peer2]) - In this case you pick a peer deterministically
//   - Block 2 has 50 txns: Peer group: [Peer 1,Peer2]
//
// Example 2:
//   Given:
//   - Peer0 = committer,validator
//   - Peer1 = validator
//   - Peer2 = validator
//   - transactionThreshold=50
//   If:
//   - Block 1 has 40 txns: Peer group: [Peer0] - The committer always has precedence since it can validate quickly locally
//   - Block 2 has 50 txns: Peer group: [Peer0,Peer1,Peer2]
//
// Should transactionThreshold be part of the policy or peer config? If it's peer config then each peer having a different value
// will screw up the algorithm.
func (e *evaluator) PeerGroups(block *cb.Block) (peergroup.PeerGroups, error) {
	logger.Debugf("[%s] Calculating peer groups to validate block %d ...", e.channelID, block.Header.Number)

	// FIXME: Should be part of policy
	transactionThreshold := 20

	validators := discovery.PeerGroup(e.Discovery.GetMembers(
		func(member *discovery.Member) bool {
			// This check would need to be removed for cross-org validation
			if member.MSPID != e.Self().MSPID || member.Properties == nil {
				return false
			}

			return roles.FromStrings(member.Properties.Roles...).Contains(roles.ValidatorRole)
		},
	))

	if len(validators) == 0 {
		logger.Infof("[%s] There are no validators for block %d", e.channelID, block.Header.Number)

		return nil, nil
	}

	var selectedValidator *discovery.Member

	if len(block.Data.Data) < transactionThreshold {
		for _, member := range validators {
			r := roles.FromStrings(member.Properties.Roles...)
			if r.Contains(roles.CommitterRole) {
				selectedValidator = member

				logger.Debugf("[%s] Selected validator is %s (committer,validator) since the number of transactions in block %d is %d which is less than the threshold %d",
					e.channelID, member.Endpoint, block.Header.Number, len(block.Data.Data), transactionThreshold)

				break
			}
		}

		if selectedValidator == nil {
			// Pick one peer deterministically
			selectedValidator = validators[block.Header.Number%uint64(len(validators))]

			logger.Infof("[%s] Selected validator is %s since the number of transactions in block %d is %d which is less than the threshold %d",
				e.channelID, selectedValidator.Endpoint, block.Header.Number, len(block.Data.Data), transactionThreshold)
		}
	}

	localEndpoint := e.Discovery.Self().Endpoint

	d, err := e.validatorDiscovery.PeersByPolicy(common.ChannelID(e.channelID), e.policy,
		func(m discimpl.NetworkMember) bool {
			endpoint := m.Endpoint
			if endpoint == "" {
				endpoint = localEndpoint
			}

			if selectedValidator != nil {
				if endpoint == selectedValidator.Endpoint {
					logger.Infof("[%s] Including peer %s since it is the selected validator for block %d (transactions: %d)",
						e.channelID, endpoint, block.Header.Number, len(block.Data.Data))

					return true
				}

				logger.Infof("[%s] Not including peer %s since the selected validator for block %d (transactions: %d) is %s",
					e.channelID, endpoint, block.Header.Number, len(block.Data.Data), selectedValidator.Endpoint)

				return false
			}

			if validators.ContainsPeer(endpoint) {
				logger.Infof("[%s] Including peer %s to validate block %d (transactions: %d)", e.channelID, endpoint, block.Header.Number, len(block.Data.Data))

				return true
			}

			logger.Infof("[%s] Not including peer %s to validate block %d (transactions: %d)", e.channelID, endpoint, block.Header.Number, len(block.Data.Data))

			return false
		},
	)
	if err != nil {
		return nil, err
	}

	desc, err := e.createValidationDescriptor(d)
	if err != nil {
		return nil, err
	}

	var peerGroups peergroup.PeerGroups
	for i, layout := range desc.layouts {
		validators, canLayoutBeSatisfied := selectPeersForLayout(desc.validatorsByGroups, layout)
		if canLayoutBeSatisfied {
			peerGroups = append(peerGroups, validators...)
			if logger.IsEnabledFor(zapcore.DebugLevel) {
				logger.Debugf("Layout %d: %s", i, validators)
			}
		}
	}

	peerGroups.Sort()

	if logger.IsEnabledFor(zapcore.DebugLevel) {
		logger.Debugf("Peer groups: %s", peerGroups)
	}

	if e.policy.MaxGroups() == 0 {
		return peerGroups, nil
	}

	// Deterministically, pick up to 'MaxGroups' groups

	startingIndex, err := e.getStartingIndex(block, len(peerGroups))
	if err != nil {
		return nil, err
	}

	logger.Debugf("Peer groups starting index for block %d: %d", block.Header.Number, startingIndex)

	var refinedPeerGroups peergroup.PeerGroups

	it := peergroup.NewIterator(peerGroups, startingIndex)
	for pg := it.Next(); pg != nil && len(refinedPeerGroups) < int(e.policy.MaxGroups()); pg = it.Next() {
		if refinedPeerGroups.ContainsAny(pg) {
			logger.Debugf("Not adding peer group [%s] since at least one peer is already in the set of peer groups %s", pg, refinedPeerGroups)
			continue
		}

		logger.Debugf("Adding unique peer group [%s]", pg)
		refinedPeerGroups = append(refinedPeerGroups, pg)
	}

	if len(refinedPeerGroups) < int(e.policy.MaxGroups()) {
		logger.Debugf("Found only %d of %d unique peer groups in set %s. Will select peer groups that have at least one unique peer...", len(refinedPeerGroups), e.policy.MaxGroups, peerGroups)

		it := peergroup.NewIterator(peerGroups, startingIndex)
		for pg := it.Next(); pg != nil && len(refinedPeerGroups) < int(e.policy.MaxGroups()); pg = it.Next() {
			if refinedPeerGroups.ContainsAll(pg) {
				logger.Debugf("Not adding peer group [%s] since all peers are already in the set of peer groups %s", pg, refinedPeerGroups)
				continue
			}

			logger.Debugf("Adding peer group with at least one unique peer [%s]", pg)
			refinedPeerGroups = append(refinedPeerGroups, pg)
		}
	}

	if logger.IsEnabledFor(zapcore.DebugLevel) {
		if len(refinedPeerGroups) < int(e.policy.MaxGroups()) {
			logger.Debugf("Found only %d of %d unique peer groups in set %s", len(refinedPeerGroups), e.policy.MaxGroups, peerGroups)
		}

		logger.Debugf("Refined peer groups: %s", refinedPeerGroups)
	}

	return refinedPeerGroups, nil
}

func (e *evaluator) Validate(validationResults []*ValidationResults) error {
	if logger.IsEnabledFor(zapcore.DebugLevel) {
		logger.Debugf("[%s] Validating validator policy for:", e.channelID)

		for _, r := range validationResults {
			logger.Infof("- from [%s], TxFlags: %+v", r.Endpoint, r.TxFlags)
		}
	}

	// If one of the results in the set came from this peer then no need to validate.
	// If one of the results in the set is from another peer in our own org then validate
	// with the 'org' policy since we should trust peers in our own org. (Note that we still
	// need to validate the signature to ensure the result came from our org.)
	for _, result := range validationResults {
		if result.Local {
			logger.Debugf("[%s] No need to validate since results for block %d originated locally", e.channelID, result.BlockNumber)
			return nil
		}

		if result.MSPID == e.Self().MSPID {
			logger.Debugf("[%s] Validating results for block %d that came from [%s] which is in our own org", e.channelID, result.BlockNumber, result.Endpoint)

			return e.orgValidator.EvaluateSignedData(getSignatureSet([]*ValidationResults{result}))
		}
	}

	logger.Debugf("[%s] Validating results for block %d which came from another org", e.channelID, validationResults[0].BlockNumber)

	return e.validator.EvaluateSignedData(getSignatureSet(validationResults))
}

func (e *evaluator) IsLocalOrgPolicy() (bool, error) {
	return e.localOrgPolicy, nil
}

func (e *evaluator) getStartingIndex(block *cb.Block, max int) (int, error) {
	h := fnv.New32a()
	_, err := h.Write(block.Header.DataHash)
	if err != nil {
		return 0, err
	}
	return int(h.Sum32()) % max, nil
}

func getSignatureSet(validationResults []*ValidationResults) []*protoutil.SignedData {
	var sigSet []*protoutil.SignedData

	for _, vr := range validationResults {
		signedData := &protoutil.SignedData{
			Data:      GetDataToSign(vr.BlockNumber, vr.TxFlags, vr.Identity),
			Signature: vr.Signature,
			Identity:  vr.Identity,
		}
		sigSet = append(sigSet, signedData)
	}

	return sigSet
}

type validationDescriptor struct {
	validatorsByGroups map[string][]*discovery.Member
	layouts            []map[string]int
}

func (e *evaluator) createValidationDescriptor(desc *gossipapi.PeerPolicyDescriptor) (*validationDescriptor, error) {
	descriptor := &validationDescriptor{
		layouts:            []map[string]int{},
		validatorsByGroups: make(map[string][]*discovery.Member),
	}
	for _, l := range desc.Layouts {
		currentLayout := make(map[string]int)
		descriptor.layouts = append(descriptor.layouts, currentLayout)
		for grp, count := range l.QuantitiesByGroup {
			if _, exists := desc.PeersByGroups[grp]; !exists {
				return nil, errors.Errorf("group %s isn't mapped to validators, but exists in a layout", grp)
			}
			currentLayout[grp] = int(count)
		}
	}

	for grp, peers := range desc.PeersByGroups {
		var validators []*discovery.Member
		for _, p := range peers.Peers {
			member, err := e.asMember(p)
			if err != nil {
				return nil, errors.Wrap(err, "failed creating endorser object")
			}
			validators = append(validators, member)
		}
		descriptor.validatorsByGroups[grp] = validators
	}

	return descriptor, nil
}

func (e *evaluator) asMember(peer *db.Peer) (*discovery.Member, error) {
	if peer.MembershipInfo == nil || peer.StateInfo == nil {
		return nil, errors.Errorf("received empty envelope(s) for validators channel %s", e.channelID)
	}

	aliveMsg, err := gprotoext.EnvelopeToGossipMessage(peer.MembershipInfo)
	if err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling gossip envelope to alive message")
	}

	stateInfMsg, err := gprotoext.EnvelopeToGossipMessage(peer.StateInfo)
	if err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling gossip envelope to state info message")
	}

	sID := &msp.SerializedIdentity{}
	if err := proto.Unmarshal(peer.Identity, sID); err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling peer's identity")
	}

	alive := aliveMsg.GetAliveMsg()
	stateInfo := stateInfMsg.GetStateInfo()

	return &discovery.Member{
		NetworkMember: discimpl.NetworkMember{
			Endpoint:   alive.Membership.Endpoint,
			PKIid:      alive.Membership.PkiId,
			Properties: stateInfo.Properties,
		},
		MSPID: sID.Mspid,
		Local: e.Self().Endpoint == alive.Membership.Endpoint,
	}, nil
}

func selectPeersForLayout(validatorsByGroups map[string][]*discovery.Member, layout map[string]int) (peergroup.PeerGroups, bool) {
	var peerGroups peergroup.PeerGroups
	for grp, count := range layout {
		validatorsOfGrp := validatorsByGroups[grp]
		if len(validatorsOfGrp) < count {
			// We couldn't select enough peers for this layout because the current group
			// requires more peers than we have available to be selected
			return nil, false
		}
		peerGroups = append(peerGroups, validatorsOfGrp)
	}

	return peergroup.NewPermutations().Groups(peerGroups...).Evaluate(), true
}

func getHash32(key string) (uint32, error) {
	h := fnv.New32a()

	_, err := h.Write([]byte(key))
	if err != nil {
		return 0, err
	}

	return h.Sum32(), nil
}

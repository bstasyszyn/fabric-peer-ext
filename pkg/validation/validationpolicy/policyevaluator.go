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
	"github.com/hyperledger/fabric/gossip/common"
	discimpl "github.com/hyperledger/fabric/gossip/discovery"
	gprotoext "github.com/hyperledger/fabric/gossip/protoext"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"

	"github.com/trustbloc/fabric-peer-ext/pkg/common/discovery"
	cvp "github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy/common"
	"github.com/trustbloc/fabric-peer-ext/pkg/validation/validationpolicy/peergroup"
)

type inquireablePolicy interface {
	policies.InquireablePolicy
	MaxGroups() int32
}

type evaluator struct {
	*discovery.Discovery
	channelID      string
	policy         inquireablePolicy
	validator      policies.Policy
	orgValidator   policies.Policy
	localOrgPolicy bool
}

func newEvaluator(channelID string, discovery *discovery.Discovery, validator, orgValidator policies.Policy, policy inquireablePolicy, localOrgPolicy bool) (*evaluator, error) {
	return &evaluator{
		channelID:      channelID,
		policy:         policy,
		validator:      validator,
		orgValidator:   orgValidator,
		Discovery:      discovery,
		localOrgPolicy: localOrgPolicy,
	}, nil
}

func (e *evaluator) PeerGroups(block *cb.Block) (peergroup.PeerGroups, error) {
	logger.Debugf("[%s] Calculating peer groups to validate block %d ...", e.channelID, block.Header.Number)

	d, err := valDiscovery.PeersForValidation(common.ChannelID(e.channelID), e.policy)
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

func (e *evaluator) createValidationDescriptor(desc *cvp.ValidationDescriptor) (*validationDescriptor, error) {
	descriptor := &validationDescriptor{
		layouts:            []map[string]int{},
		validatorsByGroups: make(map[string][]*discovery.Member),
	}
	for _, l := range desc.Layouts {
		currentLayout := make(map[string]int)
		descriptor.layouts = append(descriptor.layouts, currentLayout)
		for grp, count := range l.QuantitiesByGroup {
			if _, exists := desc.ValidatorsByGroups[grp]; !exists {
				return nil, errors.Errorf("group %s isn't mapped to validators, but exists in a layout", grp)
			}
			currentLayout[grp] = int(count)
		}
	}

	for grp, peers := range desc.ValidatorsByGroups {
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

type validatorDiscovery interface {
	PeersForValidation(chainID common.ChannelID, policy policies.InquireablePolicy) (*cvp.ValidationDescriptor, error)
}

var valDiscovery validatorDiscovery

// RegisterValidatorDiscovery registers the validator db service
func RegisterValidatorDiscovery(discovery validatorDiscovery) {
	valDiscovery = discovery
}

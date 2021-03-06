#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@txn
Feature: txn

  Background: Setup
    Given the channel "mychannel" is created and all peers have joined
    And "test" chaincode "configscc" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "AND('Org1MSP.member','Org2MSP.member')" with collection policy ""
    And "test" chaincode "testcc" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "OR('Org1MSP.member','Org2MSP.member')" with collection policy ""

    And collection config "privColl" is defined for collection "collection3" as policy="OR('Org1MSP.member','Org2MSP.member')", requiredPeerCount=1, maxPeerCount=2, and blocksToLive=3
    And "test" chaincode "target_cc" is installed from path "github.com/trustbloc/fabric-peer-ext/test/chaincode/e2e_cc" to all peers
    And "test" chaincode "target_cc" is instantiated from path "github.com/trustbloc/fabric-peer-ext/test/chaincode/e2e_cc" on the "mychannel" channel with args "" with endorsement policy "AND('Org1MSP.member','Org2MSP.member')" with collection policy "privColl"

    # We need to wait a while so that all of the peers' channel membership is Gossip'ed to all other peers.
    Then we wait 20 seconds

  @txn_s1
  Scenario: Endorsements using TXN service
    Given variable "org1Config" is assigned config from file "./fixtures/config/fabric/org1-config.json"
    And variable "org2Config" is assigned config from file "./fixtures/config/fabric/org2-config.json"

    When client invokes chaincode "configscc" with args "save,${org1Config}" on the "mychannel" channel
    And client invokes chaincode "configscc" with args "save,${org2Config}" on the "mychannel" channel
    And we wait 3 seconds

    When client queries chaincode "testcc" with args "endorseandcommit,target_cc,put,key1,value1" on peers "peer0.org1.example.com" on the "mychannel" channel
    And client queries chaincode "testcc" with args "endorseandcommit,target_cc,put,key2,value2" on peers "peer0.org2.example.com" on the "mychannel" channel
    Then we wait 5 seconds

    Then container "peer0.org2.example.com" is stopped
    And container "peer0.org2.example.com" is started

    Then container "peer1.org2.example.com" is stopped
    And container "peer1.org2.example.com" is started

    Then we wait 10 seconds

    When client queries chaincode "testcc" with args "endorseandcommit,target_cc,put,key3,value3" on peers "peer1.org1.example.com" on the "mychannel" channel
    Then we wait 5 seconds

    When client queries chaincode "testcc" with args "endorse,target_cc,get,key1" on peers "peer1.org2.example.com" on the "mychannel" channel
    Then response from "testcc" to client equal value "value1"

    When client queries chaincode "testcc" with args "endorse,target_cc,get,key2" on peers "peer0.org1.example.com" on the "mychannel" channel
    Then response from "testcc" to client equal value "value2"

    When client queries chaincode "testcc" with args "endorse,target_cc,get,key3" on peers "peer0.org2.example.com" on the "mychannel" channel
    Then response from "testcc" to client equal value "value3"

    # SDK config update
    Given variable "org1ConfigUpdate" is assigned config from file "./fixtures/config/fabric/org1-config-update.json"
    And variable "org2ConfigUpdate" is assigned config from file "./fixtures/config/fabric/org2-config-update.json"

    When client invokes chaincode "configscc" with args "save,${org1ConfigUpdate}" on the "mychannel" channel
    And client invokes chaincode "configscc" with args "save,${org2ConfigUpdate}" on the "mychannel" channel
    And we wait 5 seconds

    When client queries chaincode "testcc" with args "endorseandcommit,target_cc,put,keyA,valueA" on peers "peer0.org1.example.com" on the "mychannel" channel
    And client queries chaincode "testcc" with args "endorseandcommit,target_cc,put,keyB,valueB" on peers "peer0.org2.example.com" on the "mychannel" channel
    And we wait 5 seconds

    When client queries chaincode "testcc" with args "endorse,target_cc,get,keyA" on peers "peer1.org1.example.com" on the "mychannel" channel
    Then response from "testcc" to client equal value "valueA"

    When client queries chaincode "testcc" with args "endorse,target_cc,get,keyB" on peers "peer1.org2.example.com" on the "mychannel" channel
    Then response from "testcc" to client equal value "valueB"

  @txn_s2
  Scenario: Configuration validation errors
    Given variable "org1ConfigUpdateInvalidTxn" is assigned config from file "./fixtures/config/fabric/org1-config-invalid-txn.json"
    When client queries chaincode "configscc" with args "save,${org1ConfigUpdateInvalidTxn}" on the "mychannel" channel then the error response should contain "validation error: field 'UserID' was not specified for TXN config"

    Given variable "org1ConfigUpdateInvalidSDK" is assigned config from file "./fixtures/config/fabric/org1-config-invalid-sdk.json"
    When client queries chaincode "configscc" with args "save,${org1ConfigUpdateInvalidSDK}" on the "mychannel" channel then the error response should contain "validation error: invalid SDK config"

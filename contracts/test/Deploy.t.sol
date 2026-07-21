// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {PeregrineLightClient, ISP1Verifier} from "../src/PeregrineLightClient.sol";

contract StubVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external view {}
}

/// @title  Tests for the deployment script
/// @notice A deployment script is the *entire* security configuration of an
///         immutable contract — there is no admin key to correct a mistake with
///         afterwards. An untested one is a single typo away from a client that
///         trusts the wrong committee or, worse, a verifier that is not a
///         verifier. So the script is tested like production code.
///
/// @dev These call `deploy(...)` with explicit arguments rather than going
///      through `run()`. `vm.setEnv` writes the real process environment and
///      Foundry runs tests in parallel, so env-driven tests race each other —
///      which is exactly why `run()` was reduced to a four-line wrapper with no
///      logic in it.
contract DeployTest is Test {
    Deploy internal script;
    address internal verifierAddr;

    bytes32 internal constant VKEY = bytes32(uint256(0xABCD));
    bytes32 internal constant COMMITTEE = bytes32(uint256(0xEF01));
    uint64 internal constant CHAIN = 1;
    /// Path-compressed tree — what a current chain serves.
    uint64 internal constant TREE_V = 2;

    function setUp() public {
        script = new Deploy();
        verifierAddr = address(new StubVerifier());
    }

    /// The happy path, checked by reading the pins back off the deployed
    /// bytecode rather than off the arguments we passed in.
    function test_DeploysWithThePinsItWasGiven() public {
        PeregrineLightClient client = script.deploy(verifierAddr, VKEY, COMMITTEE, CHAIN, TREE_V);

        assertEq(address(client.verifier()), verifierAddr, "verifier");
        assertEq(client.programVKey(), VKEY, "programVKey");
        assertEq(client.committeeDigest(), COMMITTEE, "committeeDigest");
        assertEq(client.peregrineChainId(), CHAIN, "chain id");

        // A fresh client knows nothing. Anything else would mean state was
        // baked in at construction.
        assertEq(client.latestRound(), 0);
        assertEq(client.latestStoreRoot(), bytes32(0));
    }

    /// Pointing at an address with no code is the misconfiguration that would
    /// make every proof pass. It must fail before broadcast, not after.
    function test_RefusesAVerifierWithNoCodeOnThisNetwork() public {
        vm.expectRevert(bytes("SP1_VERIFIER has no code on this network"));
        script.deploy(makeAddr("notAContract"), VKEY, COMMITTEE, CHAIN, TREE_V);

        vm.expectRevert(bytes("SP1_VERIFIER has no code on this network"));
        script.deploy(address(0), VKEY, COMMITTEE, CHAIN, TREE_V);
    }

    function test_RefusesUnsetPins() public {
        vm.expectRevert(bytes("PROGRAM_VKEY must be set"));
        script.deploy(verifierAddr, bytes32(0), COMMITTEE, CHAIN, TREE_V);

        vm.expectRevert(bytes("COMMITTEE_DIGEST must be set"));
        script.deploy(verifierAddr, VKEY, bytes32(0), CHAIN, TREE_V);

        vm.expectRevert(bytes("PEREGRINE_CHAIN_ID must be set"));
        script.deploy(verifierAddr, VKEY, COMMITTEE, 0, TREE_V);
    }

    /// Two deployments with different pins are independent clients. Worth
    /// asserting because immutables are baked into bytecode, and a mistake in
    /// how they are read would surface as two "different" deployments sharing
    /// configuration.
    function test_SeparateDeploymentsDoNotShareConfiguration() public {
        PeregrineLightClient a = script.deploy(verifierAddr, VKEY, COMMITTEE, CHAIN, TREE_V);
        PeregrineLightClient b =
            script.deploy(verifierAddr, VKEY, bytes32(uint256(0x9999)), CHAIN, TREE_V);

        assertTrue(address(a) != address(b));
        assertEq(a.committeeDigest(), COMMITTEE);
        assertEq(b.committeeDigest(), bytes32(uint256(0x9999)));
    }

    /// Any well-formed configuration deploys and reports itself accurately.
    function testFuzz_PinsAreReportedBack(bytes32 vkey, bytes32 committee, uint64 chainId)
        public
    {
        vm.assume(vkey != bytes32(0) && committee != bytes32(0) && chainId != 0);
        PeregrineLightClient client = script.deploy(verifierAddr, vkey, committee, chainId, TREE_V);
        assertEq(client.programVKey(), vkey);
        assertEq(client.committeeDigest(), committee);
        assertEq(client.peregrineChainId(), chainId);
    }
}

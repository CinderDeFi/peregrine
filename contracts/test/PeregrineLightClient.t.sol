// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PeregrineLightClient, ISP1Verifier} from "../src/PeregrineLightClient.sol";

/// @notice A stand-in for SP1's verifier so the *contract's* rules can be
///         tested without a real Groth16 proof.
/// @dev The real verifier's only job is to revert on a bad proof, so a mock
///      that can be told to accept or reject exercises exactly the branch the
///      contract cares about. It is `MockSP1Verifier`, never shipped, and the
///      deployment script wires the real gateway.
contract MockSP1Verifier is ISP1Verifier {
    bool public accept = true;
    bytes32 public lastVKey;
    uint256 public calls;

    error ProofRejected();

    function setAccept(bool a) external {
        accept = a;
    }

    function verifyProof(bytes32 programVKey, bytes calldata, bytes calldata) external view {
        // `view` in the interface, so we cannot record state here; the accept
        // flag is what the tests vary.
        if (!accept) revert ProofRejected();
        programVKey; // silence unused warning
    }
}

/// @title Tests for PeregrineLightClient
/// @notice Written without forge-std so the project needs no submodules.
///         Revert expectations use low-level calls rather than cheatcodes.
contract PeregrineLightClientTest {
    MockSP1Verifier internal verifier;
    PeregrineLightClient internal client;

    bytes32 internal constant VKEY = bytes32(uint256(0xAAAA));
    uint64 internal constant CHAIN = 777;

    bytes32 internal constant TABLE = bytes32(uint256(0x1111));
    bytes32 internal constant KEY = bytes32(uint256(0x2222));
    bytes32 internal constant VALUE = bytes32(uint256(42));

    error AssertionFailed(string what);

    function setUp() public {
        verifier = new MockSP1Verifier();
        client = new PeregrineLightClient(address(verifier), VKEY, CHAIN);
    }

    // ── helpers ────────────────────────────────────────────────────────────

    function _journal(uint64 chainId, uint64 round, bytes32 storeRoot, bytes32 value)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            PeregrineLightClient.Journal({
                chainId: chainId,
                round: round,
                storeRoot: storeRoot,
                table: TABLE,
                key: KEY,
                value: value
            })
        );
    }

    function _assert(bool cond, string memory what) internal pure {
        if (!cond) revert AssertionFailed(what);
    }

    /// Call `verifyPeregrineState` and report whether it reverted.
    function _tryVerify(bytes memory publicValues) internal returns (bool ok) {
        (ok,) = address(client).call(
            abi.encodeCall(client.verifyPeregrineState, (publicValues, hex"1234"))
        );
    }

    // ── tests ──────────────────────────────────────────────────────────────

    /// A valid proof records the value and advances the root.
    function testAcceptsValidProof() public {
        setUp();
        bytes32 root = bytes32(uint256(0xC0FFEE));
        _assert(_tryVerify(_journal(CHAIN, 10, root, VALUE)), "valid proof should be accepted");

        _assert(client.latestRound() == 10, "round should advance");
        _assert(client.latestStoreRoot() == root, "root should be recorded");
        _assert(client.isVerified(root, TABLE, KEY), "value should be marked verified");
        _assert(client.getVerifiedValue(root, TABLE, KEY) == VALUE, "value should round-trip");
    }

    /// **The core rule**: if the proof does not verify, nothing is recorded.
    function testRejectsInvalidProof() public {
        setUp();
        verifier.setAccept(false);
        bytes32 root = bytes32(uint256(1));
        _assert(!_tryVerify(_journal(CHAIN, 1, root, VALUE)), "invalid proof must revert");
        _assert(client.latestRound() == 0, "nothing should be recorded");
        _assert(!client.isVerified(root, TABLE, KEY), "no value should be stored");
    }

    /// A proof for another Peregrine network must not apply here.
    function testRejectsWrongChainId() public {
        setUp();
        _assert(!_tryVerify(_journal(CHAIN + 1, 5, bytes32(uint256(2)), VALUE)), "wrong chain");
        _assert(client.latestRound() == 0, "nothing recorded");
    }

    /// Roots move forward only: an old (validly proven) checkpoint must not be
    /// replayable to resurrect stale state.
    function testRejectsStaleRound() public {
        setUp();
        _assert(_tryVerify(_journal(CHAIN, 20, bytes32(uint256(3)), VALUE)), "first update");
        _assert(!_tryVerify(_journal(CHAIN, 19, bytes32(uint256(4)), VALUE)), "stale must revert");
        _assert(client.latestRound() == 20, "round must not go backwards");
    }

    /// The same round may add more values without moving the root.
    function testSameRoundAddsValuesWithoutMovingRoot() public {
        setUp();
        bytes32 root = bytes32(uint256(5));
        _assert(_tryVerify(_journal(CHAIN, 30, root, VALUE)), "first");
        _assert(_tryVerify(_journal(CHAIN, 30, root, bytes32(uint256(43)))), "same round again");
        _assert(client.latestRound() == 30, "round unchanged");
        _assert(client.getVerifiedValue(root, TABLE, KEY) == bytes32(uint256(43)), "latest value");
    }

    /// **Unproven keys revert rather than reading zero** — the same trap
    /// `LoadEthState` avoids on the Peregrine side.
    function testUnprovenValueReverts() public {
        setUp();
        (bool ok,) = address(client).call(
            abi.encodeCall(client.getVerifiedValue, (bytes32(uint256(9)), TABLE, KEY))
        );
        _assert(!ok, "reading an unproven key must revert, not return zero");
    }

    /// A malformed journal is rejected even if the proof "verifies" — length is
    /// checked before decoding.
    function testRejectsMalformedJournal() public {
        setUp();
        _assert(!_tryVerify(hex"deadbeef"), "short public values must revert");
    }

    /// Values are namespaced by root: the same key under a different root is a
    /// different fact, and must not be readable until proven.
    function testValuesAreScopedToTheirRoot() public {
        setUp();
        bytes32 rootA = bytes32(uint256(7));
        _assert(_tryVerify(_journal(CHAIN, 40, rootA, VALUE)), "prove under rootA");
        _assert(client.isVerified(rootA, TABLE, KEY), "verified under rootA");
        _assert(!client.isVerified(bytes32(uint256(8)), TABLE, KEY), "not under another root");
    }

    /// The pinned program key is immutable — there is no setter to find.
    function testProgramVKeyIsPinned() public {
        setUp();
        _assert(client.programVKey() == VKEY, "vkey must be the pinned value");
        _assert(client.peregrineChainId() == CHAIN, "chain id must be pinned");
    }
}

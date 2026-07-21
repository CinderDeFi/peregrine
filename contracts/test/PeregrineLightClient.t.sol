// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {PeregrineLightClient, ISP1Verifier} from "../src/PeregrineLightClient.sol";

/// @notice A stand-in for SP1's verifier so the *contract's rules* can be
///         tested exhaustively without generating a Groth16 proof per case.
/// @dev The real verifier's entire contract with us is "revert on a bad proof",
///      so a mock that can be told to accept or reject exercises exactly the
///      branch this contract depends on. A real proof is exercised separately
///      in `PeregrineLightClientProof.t.sol` — that test proves the *encoding*
///      agrees with Rust; these tests prove the *logic*.
contract MockSP1Verifier is ISP1Verifier {
    bool public accept = true;

    error ProofRejected();

    function setAccept(bool a) external {
        accept = a;
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata) external view {
        if (!accept) revert ProofRejected();
    }
}

/// @notice A verifier that always accepts — used to show what the code-length
///         check in the constructor is protecting against.
contract AlwaysAccept is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external view {}
}

contract PeregrineLightClientTest is Test {
    MockSP1Verifier internal verifier;
    PeregrineLightClient internal client;

    bytes32 internal constant VKEY = bytes32(uint256(0xAAAA));
    bytes32 internal constant COMMITTEE = bytes32(uint256(0xBBBB));
    uint64 internal constant CHAIN = 777;
    /// Path-compressed tree — what a current chain serves.
    uint64 internal constant TREE_V = 2;

    bytes32 internal constant TABLE = bytes32(uint256(0x1111));
    bytes32 internal constant KEY = bytes32(uint256(0x2222));
    bytes32 internal constant VALUE = bytes32(uint256(42));

    bytes internal constant PROOF = hex"1234";

    function setUp() public {
        verifier = new MockSP1Verifier();
        client = new PeregrineLightClient(address(verifier), VKEY, COMMITTEE, CHAIN, TREE_V);
    }

    // ── helpers ────────────────────────────────────────────────────────────

    function _journal(
        uint64 chainId,
        uint64 round,
        uint64 treeVersion,
        bytes32 committee,
        bytes32 storeRoot,
        bytes32 table,
        bytes32 key,
        bytes32 value,
        uint64 valueLen
    ) internal pure returns (bytes memory) {
        return abi.encode(
            PeregrineLightClient.Journal({
                chainId: chainId,
                round: round,
                treeVersion: treeVersion,
                committeeDigest: committee,
                storeRoot: storeRoot,
                table: table,
                key: key,
                value: value,
                valueLen: valueLen
            })
        );
    }

    /// The common case: our chain, our committee, the standard table/key.
    function _ok(uint64 round, bytes32 root, bytes32 value) internal pure returns (bytes memory) {
        return _journal(CHAIN, round, TREE_V, COMMITTEE, root, TABLE, KEY, value, 32);
    }

    function _submit(bytes memory publicValues) internal returns (bytes32) {
        return client.verifyPeregrineState(publicValues, PROOF);
    }

    // ── the happy path ─────────────────────────────────────────────────────

    function test_AcceptsValidProof() public {
        bytes32 root = bytes32(uint256(0xC0FFEE));
        bytes32 got = _submit(_ok(10, root, VALUE));

        assertEq(got, VALUE, "returns the proven value");
        assertEq(client.latestRound(), 10, "round advances");
        assertEq(client.latestStoreRoot(), root, "root recorded");
        assertTrue(client.isVerified(root, TABLE, KEY), "marked verified");

        (bytes32 v, uint64 len) = client.getVerifiedValue(root, TABLE, KEY);
        assertEq(v, VALUE);
        assertEq(len, 32);
    }

    function test_EmitsValueVerified() public {
        bytes32 root = bytes32(uint256(0xC0FFEE));
        vm.expectEmit(true, true, true, true);
        emit PeregrineLightClient.ValueVerified(root, TABLE, KEY, VALUE, 32);
        _submit(_ok(10, root, VALUE));
    }

    function test_EmitsRootUpdatedOnlyWhenRoundAdvances() public {
        bytes32 root = bytes32(uint256(1));
        vm.expectEmit(true, true, false, false);
        emit PeregrineLightClient.RootUpdated(5, root);
        _submit(_ok(5, root, VALUE));

        // Same round, another key: no new RootUpdated.
        vm.recordLogs();
        _submit(_journal(CHAIN, 5, TREE_V, COMMITTEE, root, TABLE, bytes32(uint256(9)), VALUE, 32));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(
                logs[i].topics[0] != PeregrineLightClient.RootUpdated.selector,
                "root must not be re-announced at the same round"
            );
        }
    }

    // ── the core rule ──────────────────────────────────────────────────────

    /// **If the proof does not verify, nothing is recorded.** (I1)
    function test_RejectsInvalidProof() public {
        verifier.setAccept(false);
        bytes32 root = bytes32(uint256(1));

        vm.expectRevert(MockSP1Verifier.ProofRejected.selector);
        _submit(_ok(1, root, VALUE));

        assertEq(client.latestRound(), 0, "nothing recorded");
        assertFalse(client.isVerified(root, TABLE, KEY));
    }

    /// **Verification strictly precedes decoding.** A journal that is *both*
    /// unprovable and malformed must fail on the proof, not on the length —
    /// otherwise the contract is inspecting attacker data before earning the
    /// right to. This is the ordering half of I1, and a plain "it reverts"
    /// test would not catch a regression that swapped the two checks.
    function test_ProofIsCheckedBeforeJournalIsRead() public {
        verifier.setAccept(false);
        vm.expectRevert(MockSP1Verifier.ProofRejected.selector);
        client.verifyPeregrineState(hex"deadbeef", PROOF);
    }

    // ── the pins ───────────────────────────────────────────────────────────

    function test_RejectsWrongChainId() public {
        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.WrongChain.selector, CHAIN + 1, CHAIN)
        );
        _submit(_journal(CHAIN + 1, 5, TREE_V, COMMITTEE, bytes32(uint256(2)), TABLE, KEY, VALUE, 32));
        assertEq(client.latestRound(), 0);
    }

    /// A proof generated against an attacker's validator set is a *valid* proof
    /// of the pinned program. Only the committee pin distinguishes it.
    function test_RejectsWrongCommittee() public {
        bytes32 evil = bytes32(uint256(0xDEAD));
        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.WrongCommittee.selector, evil, COMMITTEE)
        );
        _submit(_journal(CHAIN, 5, TREE_V, evil, bytes32(uint256(2)), TABLE, KEY, VALUE, 32));
        assertEq(client.latestRound(), 0);
    }

    /// **The v2 upgrade pin.** Peregrine's row trees were path-compressed, and
    /// v1 and v2 commit the same state to different roots. A client pinned to
    /// one must refuse the other, or a stale-rule proof would be recorded as
    /// current state under a root that means something else.
    function test_RejectsWrongTreeVersion() public {
        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.WrongTreeVersion.selector, 1, TREE_V)
        );
        _submit(_journal(CHAIN, 5, 1, COMMITTEE, bytes32(uint256(2)), TABLE, KEY, VALUE, 32));
        assertEq(client.latestRound(), 0, "nothing recorded");
    }

    /// A client pinned to v1 mirrors that: it must refuse v2 proofs. Following
    /// a chain across its Merkle upgrade means a new deployment.
    function test_AV1ClientRefusesV2Proofs() public {
        PeregrineLightClient legacy =
            new PeregrineLightClient(address(verifier), VKEY, COMMITTEE, CHAIN, 1);
        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.WrongTreeVersion.selector, 2, 1)
        );
        legacy.verifyPeregrineState(
            _journal(CHAIN, 5, 2, COMMITTEE, bytes32(uint256(2)), TABLE, KEY, VALUE, 32),
            PROOF
        );
    }

    function test_ConstructorRejectsUnknownTreeVersion() public {
        address v = address(verifier);
        for (uint64 bad = 0; bad < 2; bad++) {
            uint64 version = bad == 0 ? 0 : 3;
            vm.expectRevert(
                abi.encodeWithSelector(
                    PeregrineLightClient.InvalidConfiguration.selector,
                    "tree version must be 1 or 2"
                )
            );
            new PeregrineLightClient(v, VKEY, COMMITTEE, CHAIN, version);
        }
    }

    function test_ProgramVKeyAndPinsAreImmutable() public view {
        assertEq(client.programVKey(), VKEY);
        assertEq(client.committeeDigest(), COMMITTEE);
        assertEq(client.peregrineChainId(), CHAIN);
        assertEq(client.treeVersion(), TREE_V);
        // There is no setter to find — this is a statement about the ABI, and
        // it is enforced by the compiler, not by this assertion.
    }

    // ── replay and equivocation ────────────────────────────────────────────

    /// Roots move forward only (I2): an old but validly proven checkpoint must
    /// not be replayable to resurrect stale state.
    function test_RejectsStaleRound() public {
        _submit(_ok(20, bytes32(uint256(3)), VALUE));
        vm.expectRevert(abi.encodeWithSelector(PeregrineLightClient.StaleRound.selector, 19, 20));
        _submit(_ok(19, bytes32(uint256(4)), VALUE));
        assertEq(client.latestRound(), 20, "round must not go backwards");
    }

    /// **Equivocation is refused, not absorbed** (I3). Two different roots at
    /// one round means a Peregrine quorum signed conflicting state; the
    /// contract must stop rather than record state under a root of the
    /// submitter's choosing.
    function test_RejectsForkedRound() public {
        bytes32 rootA = bytes32(uint256(0xA));
        bytes32 rootB = bytes32(uint256(0xB));
        _submit(_ok(30, rootA, VALUE));

        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.ForkedRound.selector, 30, rootA, rootB)
        );
        _submit(_ok(30, rootB, VALUE));

        assertFalse(client.isVerified(rootB, TABLE, KEY), "nothing under the forked root");
        assertEq(client.latestStoreRoot(), rootA);
    }

    /// The same round may add *more* keys under the *same* root.
    function test_SameRoundSameRootAddsMoreKeys() public {
        bytes32 root = bytes32(uint256(5));
        _submit(_ok(30, root, VALUE));
        bytes32 key2 = bytes32(uint256(0x3333));
        _submit(_journal(CHAIN, 30, TREE_V, COMMITTEE, root, TABLE, key2, bytes32(uint256(43)), 32));

        assertEq(client.latestRound(), 30, "round unchanged");
        (bytes32 a,) = client.getVerifiedValue(root, TABLE, KEY);
        (bytes32 b,) = client.getVerifiedValue(root, TABLE, key2);
        assertEq(a, VALUE);
        assertEq(b, bytes32(uint256(43)));
    }

    /// **A key has one value under one root** (I4). A second, different value
    /// would mean a broken guest or a BLAKE3 collision — a soundness break
    /// that must surface as a revert, never as a silent overwrite.
    function test_RejectsContradiction() public {
        bytes32 root = bytes32(uint256(7));
        _submit(_ok(40, root, VALUE));

        vm.expectRevert(
            abi.encodeWithSelector(
                PeregrineLightClient.Contradiction.selector, root, TABLE, KEY
            )
        );
        _submit(_ok(40, root, bytes32(uint256(99))));

        (bytes32 v,) = client.getVerifiedValue(root, TABLE, KEY);
        assertEq(v, VALUE, "original value survives");
    }

    /// Re-proving the *same* fact is harmless — relayers retry, and a retry
    /// must not look like an attack.
    function test_ReprovingTheSameFactIsIdempotent() public {
        bytes32 root = bytes32(uint256(7));
        _submit(_ok(40, root, VALUE));
        _submit(_ok(40, root, VALUE));
        (bytes32 v, uint64 len) = client.getVerifiedValue(root, TABLE, KEY);
        assertEq(v, VALUE);
        assertEq(len, 32);
    }

    /// Values are namespaced by root: the same key under a different root is a
    /// different fact and must not be readable until proven.
    function test_ValuesAreScopedToTheirRoot() public {
        bytes32 rootA = bytes32(uint256(7));
        _submit(_ok(40, rootA, VALUE));
        assertTrue(client.isVerified(rootA, TABLE, KEY));
        assertFalse(client.isVerified(bytes32(uint256(8)), TABLE, KEY));
    }

    // ── malformed input ────────────────────────────────────────────────────

    function test_RejectsShortJournal() public {
        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.MalformedJournal.selector, 4, 288)
        );
        client.verifyPeregrineState(hex"deadbeef", PROOF);
    }

    /// An over-long journal is rejected too. `abi.decode` would happily ignore
    /// the tail, so length is checked explicitly rather than relying on decode
    /// to fail.
    function test_RejectsOverlongJournal() public {
        bytes memory tooLong = bytes.concat(_ok(1, bytes32(uint256(1)), VALUE), hex"00");
        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.MalformedJournal.selector, 289, 288)
        );
        client.verifyPeregrineState(tooLong, PROOF);
    }

    /// A value too long to represent must not be silently truncated into one
    /// that fits.
    function test_RejectsValueTooLong() public {
        vm.expectRevert(abi.encodeWithSelector(PeregrineLightClient.ValueTooLong.selector, 33));
        _submit(_journal(CHAIN, 1, TREE_V, COMMITTEE, bytes32(uint256(1)), TABLE, KEY, VALUE, 33));
    }

    // ── reads ──────────────────────────────────────────────────────────────

    /// **Unproven keys revert rather than reading zero** (I5) — the same trap
    /// `LoadEthState` avoids on the Peregrine side.
    function test_UnprovenValueReverts() public {
        bytes32 root = bytes32(uint256(9));
        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.UnknownValue.selector, root, TABLE, KEY)
        );
        client.getVerifiedValue(root, TABLE, KEY);
    }

    /// A *legitimately zero* value is distinguishable from an absent one.
    function test_ZeroIsAValidProvenValue() public {
        bytes32 root = bytes32(uint256(11));
        _submit(_journal(CHAIN, 1, TREE_V, COMMITTEE, root, TABLE, KEY, bytes32(0), 32));
        assertTrue(client.isVerified(root, TABLE, KEY), "zero was proven, not absent");
        (bytes32 v,) = client.getVerifiedValue(root, TABLE, KEY);
        assertEq(v, bytes32(0));
    }

    function test_GetLatestValueFollowsTheNewestRoot() public {
        bytes32 rootA = bytes32(uint256(0xA));
        bytes32 rootB = bytes32(uint256(0xB));
        _submit(_ok(1, rootA, bytes32(uint256(100))));
        _submit(_ok(2, rootB, bytes32(uint256(200))));

        (bytes32 v,, uint64 round) = client.getLatestValue(TABLE, KEY);
        assertEq(v, bytes32(uint256(200)), "reads the newest root");
        assertEq(round, 2);

        // The old fact is still readable, but only if you ask for it by root.
        (bytes32 old,) = client.getVerifiedValue(rootA, TABLE, KEY);
        assertEq(old, bytes32(uint256(100)));
    }

    /// A key proven under an older root is *not* readable via the latest root:
    /// staleness must not be silently served as current.
    function test_GetLatestValueRevertsForKeyNotInNewestRoot() public {
        bytes32 rootA = bytes32(uint256(0xA));
        bytes32 rootB = bytes32(uint256(0xB));
        _submit(_ok(1, rootA, VALUE));
        _submit(_journal(CHAIN, 2, TREE_V, COMMITTEE, rootB, TABLE, bytes32(uint256(0x99)), VALUE, 32));

        vm.expectRevert(
            abi.encodeWithSelector(PeregrineLightClient.UnknownValue.selector, rootB, TABLE, KEY)
        );
        client.getLatestValue(TABLE, KEY);
    }

    /// Peregrine encodes integers little-endian; the EVM reads big-endian.
    /// `42u64` little-endian is `2a00000000000000`, which a naive big-endian
    /// read would report as 3_026_418_949_592_973_312.
    function test_GetLatestUintDecodesLittleEndian() public {
        bytes32 root = bytes32(uint256(0x1E));
        _submit(_journal(CHAIN, 1, TREE_V, COMMITTEE, root, TABLE, KEY, _leWord(42, 8), 8));
        assertEq(client.getLatestUint(TABLE, KEY), 42);
    }

    /// Right-align `len` little-endian bytes of `v` in a word, exactly as
    /// Peregrine's encoder does.
    function _leWord(uint256 v, uint64 len) internal pure returns (bytes32 out) {
        bytes memory b = new bytes(32);
        for (uint256 i = 0; i < len; i++) {
            // Truncation to the low byte is the entire point of the shift.
            // forge-lint: disable-next-line(unsafe-typecast)
            b[32 - len + i] = bytes1(uint8(v >> (8 * i)));
        }
        // `b` is allocated with exactly 32 bytes just above, so nothing is lost.
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes32(b);
    }

    function testFuzz_LittleEndianRoundTrips(uint64 v, uint8 lenSeed) public {
        uint64 len = uint64(bound(lenSeed, 8, 8)); // u64 values are 8 bytes
        bytes32 root = bytes32(uint256(keccak256(abi.encode(v))));
        _submit(_journal(CHAIN, 1, TREE_V, COMMITTEE, root, TABLE, KEY, _leWord(v, len), len));
        assertEq(client.getLatestUint(TABLE, KEY), v);
    }

    // ── constructor validation ─────────────────────────────────────────────

    /// **The most dangerous misconfiguration available.** A high-level call to
    /// an address with no code and no return data *succeeds*. Deployed against
    /// an EOA or address(0), `verifyProof` would be a no-op and every proof
    /// would be accepted. So it is impossible, not merely documented.
    function test_ConstructorRejectsVerifierWithoutCode() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                PeregrineLightClient.InvalidConfiguration.selector, "verifier has no code"
            )
        );
        new PeregrineLightClient(address(0), VKEY, COMMITTEE, CHAIN, TREE_V);

        address eoa = makeAddr("someEOA");
        vm.expectRevert(
            abi.encodeWithSelector(
                PeregrineLightClient.InvalidConfiguration.selector, "verifier has no code"
            )
        );
        new PeregrineLightClient(eoa, VKEY, COMMITTEE, CHAIN, TREE_V);
    }

    /// Demonstrates what that check buys: with a codeless verifier the
    /// contract would accept anything. (Shown against a real always-accepting
    /// *contract*, since the codeless case is now unreachable.)
    function test_AnAlwaysAcceptingVerifierWouldAcceptAnything() public {
        PeregrineLightClient loose =
            new PeregrineLightClient(address(new AlwaysAccept()), VKEY, COMMITTEE, CHAIN, TREE_V);
        loose.verifyPeregrineState(_ok(1, bytes32(uint256(1)), VALUE), hex"");
        assertEq(loose.latestRound(), 1, "the verifier is the only thing standing here");
    }

    function test_ConstructorRejectsZeroPins() public {
        address v = address(verifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                PeregrineLightClient.InvalidConfiguration.selector, "programVKey is zero"
            )
        );
        new PeregrineLightClient(v, bytes32(0), COMMITTEE, CHAIN, TREE_V);

        vm.expectRevert(
            abi.encodeWithSelector(
                PeregrineLightClient.InvalidConfiguration.selector, "committeeDigest is zero"
            )
        );
        new PeregrineLightClient(v, VKEY, bytes32(0), CHAIN, TREE_V);

        vm.expectRevert(
            abi.encodeWithSelector(
                PeregrineLightClient.InvalidConfiguration.selector, "chain id is zero"
            )
        );
        new PeregrineLightClient(v, VKEY, COMMITTEE, 0, TREE_V);
    }

    // ── the contract holds nothing (I6) ────────────────────────────────────

    function test_RejectsEther() public {
        (bool ok,) = address(client).call{value: 1 ether}("");
        assertFalse(ok, "no receive/fallback: ether must bounce");
        assertEq(address(client).balance, 0);
    }

    // ── fuzz: the pins hold for arbitrary journals ─────────────────────────

    /// No combination of journal fields gets past a wrong chain id or a wrong
    /// committee. Enumerating the negative cases by hand tests the cases I
    /// thought of; this tests the ones I didn't.
    function testFuzz_WrongPinsAlwaysRevert(
        uint64 chainId,
        uint64 round,
        bytes32 committee,
        bytes32 root,
        bytes32 value
    ) public {
        vm.assume(chainId != CHAIN || committee != COMMITTEE);
        vm.assume(root != bytes32(0));

        vm.expectRevert();
        _submit(_journal(chainId, round, TREE_V, committee, root, TABLE, KEY, value, 32));

        assertEq(client.latestRound(), 0, "nothing may be recorded");
        assertFalse(client.isVerified(root, TABLE, KEY));
    }

    /// With the right pins, any round/root/value is accepted — and read back
    /// exactly as proven.
    function testFuzz_CorrectPinsRoundTrip(uint64 round, bytes32 root, bytes32 value) public {
        vm.assume(round > 0);
        _submit(_journal(CHAIN, round, TREE_V, COMMITTEE, root, TABLE, KEY, value, 32));
        (bytes32 v,) = client.getVerifiedValue(root, TABLE, KEY);
        assertEq(v, value);
        assertEq(client.latestRound(), round);
    }
}

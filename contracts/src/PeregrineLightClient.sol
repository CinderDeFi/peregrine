// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @notice Minimal interface of SP1's on-chain verifier (`SP1VerifierGateway`).
/// @dev Only the one function this contract needs. Declaring the whole gateway
///      would invite calling parts of it we have not reasoned about.
interface ISP1Verifier {
    /// @param programVKey  Verifying-key hash of the guest program.
    /// @param publicValues ABI-encoded public values the guest committed.
    /// @param proofBytes   The Groth16 proof.
    /// @dev MUST revert if the proof is invalid. A silent `false` return is not
    ///      part of this interface, and this contract does not check one.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title  PeregrineLightClient
/// @author Peregrine contributors
/// @notice Lets Ethereum read Peregrine state trustlessly — the reciprocal of
///         Peregrine's beacon light client.
///
/// @dev # Why there is no Merkle verification in this contract
///
/// Peregrine commits state with **BLAKE3** sparse-Merkle trees. The EVM has no
/// BLAKE3 precompile, so verifying a 256-deep Peregrine inclusion proof in
/// Solidity would cost hundreds of thousands of gas per read. So we do not do
/// it here.
///
/// Instead the **whole statement is proven inside the zkVM**: the guest program
/// verifies (a) that a stake-weighted quorum of a *specific* Peregrine committee
/// signed a checkpoint committing to store root `R`, and (b) that `key` maps to
/// `value` under `R`. This contract verifies one succinct proof and reads the
/// committed journal. Gas is constant regardless of proof depth, and no BLAKE3
/// ever executes on-chain.
///
/// # The three pins
///
/// A proof is only meaningful relative to what it is a proof *of*. Three
/// immutable values fix that, and all three are checked on every call:
///
/// 1. `programVKey`     — *which program* ran. A proof of a different program is
///                        still a perfectly valid proof of something else.
/// 2. `committeeDigest` — *whose signatures* counted. Without this pin, a proof
///                        generated against an attacker's validator set is
///                        indistinguishable from one against the real set.
/// 3. `peregrineChainId`— *which network*. Stops a testnet proof applying here.
/// 4. `treeVersion`     — *which Merkle rule* the store root was computed
///                        under. Peregrine's row trees were path-compressed in
///                        the v2 upgrade, and v1 and v2 commit the same state
///                        to different roots. Without this pin a proof built
///                        against the pre-upgrade tree is indistinguishable
///                        from a current one.
///
/// None of them has a setter. An upgradeable pin is an admin key that can
/// redefine what every past and future proof meant, which would make the
/// cryptography decorative.
///
/// # Invariants
///
/// - **I1.** No storage is written unless `verifier.verifyProof` returned
///   without reverting. Verification strictly precedes any use of
///   `publicValues`.
/// - **I2.** `latestRound` is non-decreasing.
/// - **I3.** For a given `round`, at most one `storeRoot` is ever accepted.
///   Equivocation reverts rather than being silently absorbed.
/// - **I4.** For a given `(storeRoot, table, key)`, at most one `value` is ever
///   recorded. A contradiction reverts; it would mean a broken guest or a
///   BLAKE3 collision, and must never be quietly overwritten.
/// - **I5.** `getVerifiedValue` never returns a value that was not proven. It
///   reverts instead of returning zero.
/// - **I6.** The contract holds no ether, has no owner, no pause, and no
///   upgrade path. There is nothing to steal and no privileged action.
///
/// @custom:security-contact security@peregrine.example
/// @custom:status UNAUDITED. Compiled and tested under Foundry (38 tests,
/// including fuzzing and a cross-language encoding check against Rust-generated
/// bytes), and clean under Slither. The end-to-end path against a **real** SP1
/// Groth16 proof is written (`test/PeregrineProofE2E.t.sol`) but has **not yet
/// been executed** — generating the proof needs Docker, which was unavailable
/// in the development environment. Never third-party reviewed, never deployed.
/// Do not put value behind it.
contract PeregrineLightClient {
    // ─────────────────────────────────────────────────────────────────────────
    // Immutable configuration — the trust roots.
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice SP1 verifier (gateway) used to check proofs.
    ISP1Verifier public immutable verifier;

    /// @notice Verifying-key hash of the Peregrine state guest program.
    bytes32 public immutable programVKey;

    /// @notice Digest of the Peregrine committee whose signatures the guest is
    ///         required to have counted.
    /// @dev This is the contract's root of trust in Peregrine's validator set.
    ///      Committee **rotation is not implemented**: following a rotating set
    ///      requires proving each transition from the previous one, which this
    ///      scaffold does not do. A rotation therefore means deploying a new
    ///      client. That is a real limitation, stated here rather than hidden.
    bytes32 public immutable committeeDigest;

    /// @notice Peregrine chain id this client accepts.
    uint64 public immutable peregrineChainId;

    /// @notice Sparse-Merkle rule this client accepts (1 = v1, 2 = v2).
    /// @dev Immutable like the other pins. Following a chain across its Merkle
    ///      upgrade means deploying a new client, which is the honest cost of
    ///      refusing an admin key that could redefine what a root means.
    uint64 public immutable treeVersion;

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Highest checkpoint round accepted so far.
    uint64 public latestRound;

    /// @notice Store root at `latestRound`.
    bytes32 public latestStoreRoot;

    /// @dev Verified values, keyed by `keccak256(storeRoot, table, key)`.
    ///      Split from `_known` rather than using a sentinel so that a
    ///      legitimately-zero value is distinguishable from an absent one.
    mapping(bytes32 => bytes32) private _values;
    mapping(bytes32 => uint64) private _valueLens;
    mapping(bytes32 => bool) private _known;

    /// @dev Store root accepted at each round, for the equivocation check (I3).
    mapping(uint64 => bytes32) private _rootAtRound;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice A new, higher checkpoint round was accepted.
    event RootUpdated(uint64 indexed round, bytes32 indexed storeRoot);

    /// @notice A value was proven under `storeRoot`.
    /// @param valueLen True byte length of the Peregrine value; `value` is the
    ///        left-padded (right-aligned) big-endian encoding of those bytes.
    event ValueVerified(
        bytes32 indexed storeRoot,
        bytes32 indexed table,
        bytes32 indexed key,
        bytes32 value,
        uint64 valueLen
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Errors — every failure mode is a distinct, named revert.
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Journal is for a different Peregrine network.
    error WrongChain(uint64 got, uint64 expected);
    /// @notice Journal counted signatures from a committee we do not trust.
    error WrongCommittee(bytes32 got, bytes32 expected);
    /// @notice Journal's store root was computed under a different Merkle rule.
    error WrongTreeVersion(uint64 got, uint64 expected);
    /// @notice Journal is older than the newest checkpoint already accepted.
    error StaleRound(uint64 got, uint64 latest);
    /// @notice Two different store roots were proven for the same round.
    /// @dev A quorum of Peregrine equivocated, or a pin is wrong. Either way
    ///      this contract stops rather than choosing a side.
    error ForkedRound(uint64 round, bytes32 have, bytes32 got);
    /// @notice Two different values were proven for the same key under the same
    ///         root — a soundness break, not a normal condition.
    error Contradiction(bytes32 storeRoot, bytes32 table, bytes32 key);
    /// @notice The requested key was never proven under that root.
    error UnknownValue(bytes32 storeRoot, bytes32 table, bytes32 key);
    /// @notice `publicValues` is not a well-formed journal.
    error MalformedJournal(uint256 length, uint256 expected);
    /// @notice A value longer than 32 bytes cannot be represented on-chain.
    error ValueTooLong(uint64 valueLen);
    /// @notice Constructor argument failed validation.
    error InvalidConfiguration(string what);

    // ─────────────────────────────────────────────────────────────────────────
    // Journal
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice The public values the guest commits.
    /// @dev Field order and types are consensus with the Rust side
    ///      (`peregrine-interop::state::encode_state_journal`). All fields are
    ///      static, so `abi.encode` of this struct is exactly
    ///      `JOURNAL_BYTES` bytes of concatenated 32-byte words and the Rust
    ///      encoder can be — and is — a hand-written concatenation.
    ///      Changing either side without the other silently misreads every
    ///      proof, so both are tested against one shared fixture.
    struct Journal {
        uint64 chainId;
        uint64 round;
        uint64 treeVersion;
        bytes32 committeeDigest;
        bytes32 storeRoot;
        bytes32 table;
        bytes32 key;
        bytes32 value;
        uint64 valueLen;
    }

    /// @notice Exact expected length of `publicValues`.
    uint256 public constant JOURNAL_BYTES = 9 * 32;

    /// @param _verifier        SP1 verifier gateway. Must be a contract.
    /// @param _programVKey     Verifying-key hash of the state guest.
    /// @param _committeeDigest Digest of the trusted Peregrine committee.
    /// @param _peregrineChainId Peregrine network id to accept.
    /// @param _treeVersion Sparse-Merkle rule to accept (1 = v1, 2 = v2).
    constructor(
        address _verifier,
        bytes32 _programVKey,
        bytes32 _committeeDigest,
        uint64 _peregrineChainId,
        uint64 _treeVersion
    ) {
        // A call to an address with no code and no return data *succeeds*.
        // Without this check, deploying against address(0) — or any EOA —
        // would make `verifyProof` a no-op and every proof would be accepted.
        // This is the single most dangerous misconfiguration available, so it
        // is impossible rather than documented.
        if (_verifier.code.length == 0) revert InvalidConfiguration("verifier has no code");
        if (_programVKey == bytes32(0)) revert InvalidConfiguration("programVKey is zero");
        if (_committeeDigest == bytes32(0)) revert InvalidConfiguration("committeeDigest is zero");
        if (_peregrineChainId == 0) revert InvalidConfiguration("chain id is zero");
        // Only the two rules that exist. A zero or unknown version would pin
        // this client to a tree nobody produces, which fails closed but reads
        // as a working deployment until the first proof arrives.
        if (_treeVersion != 1 && _treeVersion != 2) {
            revert InvalidConfiguration("tree version must be 1 or 2");
        }

        verifier = ISP1Verifier(_verifier);
        programVKey = _programVKey;
        committeeDigest = _committeeDigest;
        peregrineChainId = _peregrineChainId;
        treeVersion = _treeVersion;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Write path
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Verify a proof of Peregrine state and record the value.
    /// @param publicValues ABI-encoded `Journal` committed by the guest.
    /// @param proofBytes   SP1 Groth16 proof.
    /// @return value The proven value, right-aligned in a `bytes32`.
    ///
    /// @dev Order matters and is the core of I1: the proof is checked *before*
    ///      a single field of `publicValues` is read. Decoding first and
    ///      validating later is how verifiers end up acting on attacker-chosen
    ///      data.
    ///
    ///      Permissionless by design. Anyone may submit a proof; the proof is
    ///      the authorization, so there is no caller to trust and no access
    ///      control to get wrong. The cost of a wrong submission is the gas the
    ///      submitter already paid.
    ///
    ///      Not reentrant: the only external call is a `view` on an immutable,
    ///      code-verified address, and it happens before any state write.
    ///
    ///      The return value is only observable to on-chain callers. An
    ///      off-chain caller sending this as a transaction must read the value
    ///      back with {getVerifiedValue} or from the {ValueVerified} log — a
    ///      transaction's return data is not available to a receipt.
    function verifyPeregrineState(bytes calldata publicValues, bytes calldata proofBytes)
        external
        returns (bytes32 value)
    {
        // (1) Cryptography first. Reverts on an invalid proof. The pinned
        //     programVKey is what ties this proof to *our* program.
        verifier.verifyProof(programVKey, publicValues, proofBytes);

        // (2) Only now is it safe to look at the journal. Length is checked
        //     before decoding: `abi.decode` on a short buffer reverts, but on
        //     an over-long one it would silently ignore the tail.
        if (publicValues.length != JOURNAL_BYTES) {
            revert MalformedJournal(publicValues.length, JOURNAL_BYTES);
        }
        Journal memory j = abi.decode(publicValues, (Journal));

        // (3) The pins. Right network, right validator set.
        if (j.chainId != peregrineChainId) revert WrongChain(j.chainId, peregrineChainId);
        if (j.committeeDigest != committeeDigest) {
            revert WrongCommittee(j.committeeDigest, committeeDigest);
        }
        // The store root only means what we think it means under the rule it
        // was computed with; a v1 root and a v2 root over identical state are
        // different 32-byte values.
        if (j.treeVersion != treeVersion) {
            revert WrongTreeVersion(j.treeVersion, treeVersion);
        }

        // (4) A value we cannot represent must not be truncated into one we
        //     can. The guest enforces this too; enforcing it on both sides
        //     means a guest bug cannot become a silent misread here.
        if (j.valueLen > 32) revert ValueTooLong(j.valueLen);

        // (5) Rounds move forward only (I2). Without this, an old but validly
        //     proven checkpoint could be replayed to resurrect stale state.
        if (j.round < latestRound) revert StaleRound(j.round, latestRound);

        // (6) Equivocation check (I3). At a round we have already seen, the
        //     root must be the one we saw. Two roots at one round means a
        //     Peregrine quorum signed conflicting state; absorbing that
        //     silently would let an attacker who achieved it write whatever
        //     they liked under a root of their choosing.
        bytes32 seenRoot = _rootAtRound[j.round];
        if (seenRoot != bytes32(0) && seenRoot != j.storeRoot) {
            revert ForkedRound(j.round, seenRoot, j.storeRoot);
        }
        if (seenRoot == bytes32(0)) _rootAtRound[j.round] = j.storeRoot;

        if (j.round > latestRound) {
            latestRound = j.round;
            latestStoreRoot = j.storeRoot;
            emit RootUpdated(j.round, j.storeRoot);
        }

        // (7) Record. Contradiction is a soundness break (I4), not an update:
        //     under a fixed root a key has exactly one value, so a second,
        //     different value means the guest or the tree is broken.
        bytes32 slot = _slot(j.storeRoot, j.table, j.key);
        if (_known[slot] && (_values[slot] != j.value || _valueLens[slot] != j.valueLen)) {
            revert Contradiction(j.storeRoot, j.table, j.key);
        }
        _values[slot] = j.value;
        _valueLens[slot] = j.valueLen;
        _known[slot] = true;

        emit ValueVerified(j.storeRoot, j.table, j.key, j.value, j.valueLen);
        return j.value;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Read path
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Read a previously-verified value under an explicit root.
    /// @dev Reverts when the value was never proven (I5). Returning zero for an
    ///      unproven key would let a caller mistake "not verified" for "is
    ///      zero" — the same trap Peregrine's `LoadEthState` avoids in the
    ///      other direction.
    ///
    ///      ⚠️ Callers that pass a caller-supplied `storeRoot` are trusting
    ///      whoever chose it: an *old* root holds genuinely proven but stale
    ///      values. Prefer {getLatestValue} unless you specifically want a
    ///      historical read.
    function getVerifiedValue(bytes32 storeRoot, bytes32 table, bytes32 key)
        external
        view
        returns (bytes32 value, uint64 valueLen)
    {
        bytes32 slot = _slot(storeRoot, table, key);
        if (!_known[slot]) revert UnknownValue(storeRoot, table, key);
        return (_values[slot], _valueLens[slot]);
    }

    /// @notice Read a value under the newest root this client has accepted.
    /// @dev The safe default, and the reason it exists: it removes the caller's
    ///      opportunity to be handed a stale root. Still reverts rather than
    ///      returning zero if the key was not proven under that root.
    function getLatestValue(bytes32 table, bytes32 key)
        external
        view
        returns (bytes32 value, uint64 valueLen, uint64 round)
    {
        bytes32 root = latestStoreRoot;
        bytes32 slot = _slot(root, table, key);
        if (!_known[slot]) revert UnknownValue(root, table, key);
        return (_values[slot], _valueLens[slot], latestRound);
    }

    /// @notice Read a value as a `uint256`.
    /// @dev Convenience for the common case (a price, a count). Peregrine
    ///      encodes integers little-endian; Solidity reads big-endian, so the
    ///      bytes are reversed here rather than in every consumer.
    function getLatestUint(bytes32 table, bytes32 key) external view returns (uint256) {
        bytes32 root = latestStoreRoot;
        bytes32 slot = _slot(root, table, key);
        if (!_known[slot]) revert UnknownValue(root, table, key);
        return _leToUint(_values[slot], _valueLens[slot]);
    }

    /// @notice Whether a value has been verified under a given root.
    /// @dev The non-reverting probe, for callers that want to branch rather
    ///      than fail.
    function isVerified(bytes32 storeRoot, bytes32 table, bytes32 key) external view returns (bool) {
        return _known[_slot(storeRoot, table, key)];
    }

    /// @notice The store root accepted at `round`, or zero if none was.
    function rootAtRound(uint64 round) external view returns (bytes32) {
        return _rootAtRound[round];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internals
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev `encodePacked` is safe here despite the usual collision warning:
    ///      all three operands are fixed-width `bytes32`, so the concatenation
    ///      is unambiguous. It would not be safe if any were dynamic.
    function _slot(bytes32 storeRoot, bytes32 table, bytes32 key) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(storeRoot, table, key));
    }

    /// @dev Interpret the low `len` bytes of a right-aligned word as a
    ///      little-endian integer. `len` is bounded by 32 at the write path, so
    ///      the loop is bounded and cannot overflow the word.
    function _leToUint(bytes32 word, uint64 len) private pure returns (uint256 out) {
        for (uint256 i = 0; i < len; i++) {
            // Byte i of the value sits at position 32-len+i in the word.
            uint256 b = uint256(uint8(word[32 - len + i]));
            out |= b << (8 * i);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @notice Minimal interface of SP1's on-chain verifier (SP1VerifierGateway).
interface ISP1Verifier {
    /// @param programVKey  Verifying-key hash of the guest program.
    /// @param publicValues ABI-encoded public values the guest committed.
    /// @param proofBytes   The Groth16/PLONK proof.
    /// @dev Reverts if the proof is invalid.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title PeregrineLightClient
/// @notice Lets Ethereum read Peregrine state trustlessly — the reciprocal of
///         Peregrine's beacon light client.
///
/// @dev ## Why there is no Merkle verification in this contract
///
/// Peregrine commits state with **BLAKE3** sparse-Merkle trees. The EVM has no
/// BLAKE3 precompile, so verifying a Peregrine inclusion proof directly in
/// Solidity would cost on the order of hundreds of thousands of gas per proof —
/// and a 256-deep SMT path makes it worse. So we do not do it here.
///
/// Instead the **whole statement is proven inside the zkVM**: the guest program
/// verifies (a) that a stake-weighted quorum of Peregrine's committee signed a
/// checkpoint committing to store root `R`, and (b) that `key` maps to `value`
/// under `R`. This contract then verifies one succinct proof and reads the
/// committed journal. Gas is constant regardless of proof depth, and no BLAKE3
/// is ever executed on-chain.
///
/// ## Trust assumptions, stated plainly
///
/// 1. **SP1's Groth16 verifier.** Groth16 requires a circuit-specific trusted
///    setup, performed by Succinct. If you cannot accept that, this contract is
///    not for you — there is no non-trusted-setup path that is cheap enough for
///    L1 today. Peregrine's *own* verification of Ethereum uses SP1 Compressed
///    (STARK, no trusted setup); the asymmetry is deliberate and is a property
///    of the EVM, not of the protocol.
/// 2. **The pinned program.** `programVKey` is immutable. A proof of a
///    different program is still a valid proof, so pinning is the check that
///    makes a proof mean what we think it means.
/// 3. **Peregrine's validator set.** The guest checks a stake-weighted quorum
///    against a committee it is told about. Committee *rotation* is not yet
///    implemented (see the README), so today the committee is fixed at the
///    guest's compile time — that is the weakest link in this direction and it
///    is why this contract is not yet suitable for value.
///
/// @custom:status UNAUDITED AND UNDEPLOYED. This contract has never been
/// compiled by a Solidity toolchain, deployed, or tested against a real SP1
/// proof — there is no EVM toolchain in the development environment it was
/// written in. Treat it as a specification of the intended interface.
contract PeregrineLightClient {
    /// @notice SP1 verifier (gateway) used to check proofs.
    ISP1Verifier public immutable verifier;

    /// @notice Verifying-key hash of the Peregrine state guest program.
    /// @dev Immutable on purpose: an upgradeable vkey is an admin key that can
    ///      swap in a program that commits anything.
    bytes32 public immutable programVKey;

    /// @notice Peregrine chain id this client accepts (rejects other networks).
    uint64 public immutable peregrineChainId;

    /// @notice Highest checkpoint round accepted so far.
    uint64 public latestRound;

    /// @notice Store root at `latestRound`.
    bytes32 public latestStoreRoot;

    /// @notice Verified values, keyed by `keccak256(storeRoot, table, key)`.
    mapping(bytes32 => bytes32) private _values;
    mapping(bytes32 => bool) private _known;

    event RootUpdated(uint64 indexed round, bytes32 indexed storeRoot);
    event ValueVerified(bytes32 indexed storeRoot, bytes32 indexed table, bytes32 key, bytes32 value);

    error WrongChain(uint64 got, uint64 expected);
    error StaleRound(uint64 got, uint64 latest);
    error UnknownValue();
    error MalformedJournal();

    /// The journal the guest commits. Field order and types are consensus with
    /// the Rust side — changing either without changing the other silently
    /// misreads every proof, so both are derived from one definition.
    struct Journal {
        uint64 chainId;
        uint64 round;
        bytes32 storeRoot;
        bytes32 table;
        bytes32 key;
        bytes32 value;
    }

    constructor(address _verifier, bytes32 _programVKey, uint64 _peregrineChainId) {
        verifier = ISP1Verifier(_verifier);
        programVKey = _programVKey;
        peregrineChainId = _peregrineChainId;
    }

    /// @notice Verify a proof of Peregrine state and record the value.
    /// @param publicValues ABI-encoded `Journal` committed by the guest.
    /// @param proofBytes   SP1 Groth16 proof.
    ///
    /// @dev Order matters: we verify the proof *before* trusting a single field
    ///      of `publicValues`. Decoding first and validating later is how
    ///      verifiers end up acting on attacker-chosen data.
    function verifyPeregrineState(bytes calldata publicValues, bytes calldata proofBytes)
        external
        returns (bytes32 value)
    {
        // (1) Cryptography first. Reverts on an invalid proof. The pinned
        //     programVKey is what ties this proof to *our* program.
        verifier.verifyProof(programVKey, publicValues, proofBytes);

        // (2) Only now is it safe to read the journal.
        if (publicValues.length != 6 * 32) revert MalformedJournal();
        Journal memory j = abi.decode(publicValues, (Journal));

        // (3) Right chain.
        if (j.chainId != peregrineChainId) revert WrongChain(j.chainId, peregrineChainId);

        // (4) Roots move forward only. Without this, an old (validly proven)
        //     checkpoint could be replayed to resurrect stale state.
        if (j.round < latestRound) revert StaleRound(j.round, latestRound);
        if (j.round > latestRound) {
            latestRound = j.round;
            latestStoreRoot = j.storeRoot;
            emit RootUpdated(j.round, j.storeRoot);
        }

        bytes32 slot = _slot(j.storeRoot, j.table, j.key);
        _values[slot] = j.value;
        _known[slot] = true;
        emit ValueVerified(j.storeRoot, j.table, j.key, j.value);
        return j.value;
    }

    /// @notice Read a previously-verified value.
    /// @dev Reverts when the value was never proven. Returning zero for an
    ///      unproven key would let a caller mistake "not verified" for "is
    ///      zero" — the same trap Peregrine's `LoadEthState` avoids in the
    ///      other direction.
    function getVerifiedValue(bytes32 storeRoot, bytes32 table, bytes32 key)
        external
        view
        returns (bytes32)
    {
        bytes32 slot = _slot(storeRoot, table, key);
        if (!_known[slot]) revert UnknownValue();
        return _values[slot];
    }

    /// @notice Whether a value has been verified under a given root.
    function isVerified(bytes32 storeRoot, bytes32 table, bytes32 key) external view returns (bool) {
        return _known[_slot(storeRoot, table, key)];
    }

    function _slot(bytes32 storeRoot, bytes32 table, bytes32 key) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(storeRoot, table, key));
    }
}

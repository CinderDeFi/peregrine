// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {PeregrineLightClient} from "../src/PeregrineLightClient.sol";

/// @title  Deploy PeregrineLightClient
///
/// @notice Every constructor argument is immutable once deployed, so getting
///         them right *here* is the entire security configuration of the
///         deployment. There is no admin key to fix a mistake with — that is
///         the point, and it is why this script re-checks each one.
///
/// * `SP1_VERIFIER`       — the SP1 verifier gateway on this network. Take the
///                          address from Succinct's published deployments, not
///                          from whoever will be sending you proofs.
/// * `PROGRAM_VKEY`       — verifying-key hash of the Peregrine state guest.
///                          **Derive this from your own build of the guest**
///                          (`cargo prove build` → `peregrine-state-guest`),
///                          never from the party supplying the proofs. A vkey
///                          you were handed is a program you did not choose.
/// * `COMMITTEE_DIGEST`   — digest of the Peregrine committee you trust. This
///                          is the root of trust in Peregrine's validator set;
///                          compute it from a validator set you verified out of
///                          band.
/// * `PEREGRINE_CHAIN_ID` — the Peregrine network whose state this accepts.
/// * `TREE_VERSION`       — the sparse-Merkle rule to accept: `1` for the
///                          original dense tree, `2` for the path-compressed
///                          one. A chain that has migrated serves v2 roots, and
///                          a client pinned to v1 will reject every proof from
///                          it — deliberately, because a v1 root and a v2 root
///                          over the same state are different values.
///
/// Usage:
/// ```bash
/// export SP1_VERIFIER=0x...        # SP1VerifierGateway on your network
/// export PROGRAM_VKEY=0x...        # from YOUR build of the guest
/// export COMMITTEE_DIGEST=0x...    # `peregrine committee-digest`
/// export PEREGRINE_CHAIN_ID=1
/// export TREE_VERSION=2                # 1 = pre-upgrade, 2 = path-compressed
/// forge script script/Deploy.s.sol:Deploy \
///   --rpc-url "$RPC_URL" --private-key "$PK" --broadcast
/// ```
contract Deploy is Script {
    /// @notice Read the configuration from the environment and deploy.
    /// @dev A thin wrapper over {deploy} on purpose: environment reading is the
    ///      one part that cannot be unit-tested (`vm.setEnv` writes the real
    ///      process environment, and Foundry runs tests in parallel, so
    ///      env-based tests race each other). Keeping it to four lines with no
    ///      logic means there is almost nothing here to get wrong, and
    ///      everything that *could* be wrong lives in {deploy}, which is tested.
    function run() external returns (PeregrineLightClient) {
        return deploy(
            vm.envAddress("SP1_VERIFIER"),
            vm.envBytes32("PROGRAM_VKEY"),
            vm.envBytes32("COMMITTEE_DIGEST"),
            uint64(vm.envUint("PEREGRINE_CHAIN_ID")),
            uint64(vm.envUint("TREE_VERSION"))
        );
    }

    /// @notice Deploy with explicit pins, validating each one first.
    function deploy(
        address verifier,
        bytes32 programVKey,
        bytes32 committeeDigest,
        uint64 chainId,
        uint64 treeVersion
    ) public returns (PeregrineLightClient client) {
        // The constructor enforces all of this too. Checking here as well turns
        // a failed transaction (gas spent, nothing deployed, error buried in a
        // trace) into a clear message before anything is broadcast.
        require(verifier.code.length > 0, "SP1_VERIFIER has no code on this network");
        require(programVKey != bytes32(0), "PROGRAM_VKEY must be set");
        require(committeeDigest != bytes32(0), "COMMITTEE_DIGEST must be set");
        require(chainId != 0, "PEREGRINE_CHAIN_ID must be set");
        require(treeVersion == 1 || treeVersion == 2, "TREE_VERSION must be 1 or 2");

        console2.log("verifier        ", verifier);
        console2.logBytes32(programVKey);
        console2.logBytes32(committeeDigest);
        console2.log("peregrine chain ", chainId);
        console2.log("tree version    ", treeVersion);

        vm.startBroadcast();
        client =
            new PeregrineLightClient(verifier, programVKey, committeeDigest, chainId, treeVersion);
        vm.stopBroadcast();

        // Read the pins back off the deployed contract rather than trusting the
        // constructor arguments we passed: this is the only check that proves
        // the bytecode on-chain is configured the way we intended.
        require(address(client.verifier()) == verifier, "verifier mismatch");
        require(client.programVKey() == programVKey, "vkey mismatch");
        require(client.committeeDigest() == committeeDigest, "committee mismatch");
        require(client.peregrineChainId() == chainId, "chain id mismatch");
        require(client.treeVersion() == treeVersion, "tree version mismatch");

        console2.log("deployed        ", address(client));
    }
}

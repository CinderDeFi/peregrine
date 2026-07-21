// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PeregrineLightClient} from "../src/PeregrineLightClient.sol";

/// @dev The subset of Foundry's cheatcode interface this script needs.
///      Declared inline so the project stays free of submodules — see
///      `foundry.toml`.
interface Vm {
    function envAddress(string calldata name) external view returns (address);
    function envBytes32(string calldata name) external view returns (bytes32);
    function envUint(string calldata name) external view returns (uint256);
    function startBroadcast() external;
    function stopBroadcast() external;
}

/// @title Deploy PeregrineLightClient
///
/// @notice Every constructor argument is immutable once deployed, so getting
///         them right *here* is the whole security configuration:
///
/// * `SP1_VERIFIER`       — the SP1 verifier gateway for this network.
/// * `PROGRAM_VKEY`       — verifying-key hash of the Peregrine state guest.
///                          **Obtain this from your own build of the guest**
///                          (`cargo prove build`), never from the party that
///                          will be supplying you proofs.
/// * `PEREGRINE_CHAIN_ID` — the Peregrine network whose state this accepts.
///
/// Usage:
/// ```bash
/// export SP1_VERIFIER=0x...            # SP1VerifierGateway on your network
/// export PROGRAM_VKEY=0x...            # from the guest build
/// export PEREGRINE_CHAIN_ID=1
/// forge script script/Deploy.s.sol:Deploy \
///   --rpc-url "$RPC_URL" --private-key "$PK" --broadcast
/// ```
contract Deploy {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (PeregrineLightClient client) {
        address verifier = vm.envAddress("SP1_VERIFIER");
        bytes32 programVKey = vm.envBytes32("PROGRAM_VKEY");
        uint64 chainId = uint64(vm.envUint("PEREGRINE_CHAIN_ID"));

        // A zero vkey would accept a proof of *any* program; refuse to deploy a
        // contract that is trivially forgeable.
        require(programVKey != bytes32(0), "PROGRAM_VKEY must be set");
        require(verifier != address(0), "SP1_VERIFIER must be set");

        vm.startBroadcast();
        client = new PeregrineLightClient(verifier, programVKey, chainId);
        vm.stopBroadcast();
    }
}

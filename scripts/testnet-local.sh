#!/usr/bin/env bash
# Spin up a local Peregrine testnet from a fresh genesis, with a faucet.
#
# Generates a genesis + keys under $DIR, then runs the validator committee with a
# client RPC endpoint. Start the gateway and faucet in separate terminals (see
# the printed hints, or docs/TESTNET.md).
#
#   CHAIN_ID=424242 VALIDATORS=4 DIR=./testnet ./scripts/testnet-local.sh
set -euo pipefail

CHAIN_ID="${CHAIN_ID:-424242}"
VALIDATORS="${VALIDATORS:-4}"
NETWORK="${NETWORK:-peregrine-testnet-local}"
DIR="${DIR:-./testnet}"
RPC_ADDR="${RPC_ADDR:-127.0.0.1:9000}"

# Prefer an installed binary; fall back to `cargo run`.
if command -v peregrine >/dev/null 2>&1; then
  PEREGRINE="peregrine"
else
  PEREGRINE="cargo run -q -p peregrine-cli --"
fi

mkdir -p "$DIR"
cd "$DIR"

if [ ! -f genesis.toml ]; then
  echo "==> generating genesis (chain id $CHAIN_ID, $VALIDATORS validators)"
  $PEREGRINE genesis new \
    --validators "$VALIDATORS" --chain-id "$CHAIN_ID" --network "$NETWORK" \
    --out genesis.toml --keys-dir testnet-keys
else
  echo "==> reusing existing genesis.toml"
fi

$PEREGRINE genesis show genesis.toml

cat <<EOF

==> starting the network on $RPC_ADDR
    In other terminals:
      $PEREGRINE gateway      --node $RPC_ADDR --bind 127.0.0.1:8080
      $PEREGRINE faucet serve --node $RPC_ADDR --faucet-key $DIR/testnet-keys/faucet.key
    Get tokens:
      $PEREGRINE faucet drip <your-hex-pubkey> --faucet-key $DIR/testnet-keys/faucet.key
    Press Ctrl-C to stop.

EOF

exec $PEREGRINE node run --genesis genesis.toml --keys-dir testnet-keys --rpc-addr "$RPC_ADDR"

### What this changes

### Why

### Checklist

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Touched interop? `cargo test -p peregrine-interop --features bls`
- [ ] Touched contracts? `cd contracts && forge test`
- [ ] Touched proof formats? Regenerated the cross-language fixture
      (`cargo run -p peregrine-node --example gen_js_fixture`) and `cd sdk/js && npm test`

(`make ci` runs the whole set.)

### Security / honesty

- [ ] New consensus, proof, or VM logic has a test that **fails without it**,
      including the adversarial case
- [ ] If this is a stub, shortcut, or partial implementation, it is documented
      in the README's *Honest limitations* — a documented stub beats an
      undocumented one
- [ ] No new claim of a security property that isn't enforced by a test

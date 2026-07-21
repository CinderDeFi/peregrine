//! # peregrine-vm — TalonVM (bootstrap stub)
//!
//! The real TalonVM is an RV64 RISC-V core with JIT/AOT and cycle-accurate
//! metering (design doc §4.4). This stub exists to lock in the contracts
//! everything else programs against, so swapping in the RISC-V core later is an
//! implementation change, not an interface change:
//!
//! 1. **Deterministic, metered execution** — every instruction charges the
//!    compute meter; host data ops charge the data meter. Metering is part of
//!    the interpreter, not the host, so costs are consensus-identical on every
//!    validator. Crucially, **gas is charged even when a transaction traps**
//!    (out-of-compute, stack fault, bad jump, host error) — the meter is always
//!    returned, so a program cannot buy free computation by failing late.
//! 2. **Bounded by construction** — every instruction costs ≥1 CU against a
//!    fixed budget, so any loop halts (out-of-compute); a stack-depth cap and
//!    jump-target validation close the other unbounded paths.
//! 3. **Data-native host calls** — `table_insert` / `table_read` /
//!    `table_read_proven` / `stream_emit` are VM primitives (not contract
//!    patterns), expressed via the [`Host`] trait implemented by the node. A
//!    proven read is *data-priced for its proof bytes*, making the cost of
//!    verifiable/stateless reads explicit.
//! 4. **Polyglot call surface** — [`Vm::call_evm`] is the mounting point for
//!    the EVM-bytecode transpiler; today it deterministically lowers an
//!    "EVM-like" call descriptor to a Talon program so EVM-shaped traffic flows
//!    through the same metering + host path end to end.

use peregrine_core::Hash;
use peregrine_data::fees::DualMeter;
use peregrine_data::tables::TableId;
use serde::{Deserialize, Serialize};

/// Per-instruction compute cost (bootstrap flat model; production is
/// cycle-accurate from the RISC-V core).
const CU_PER_INSTRUCTION: u64 = 1;
/// Base surcharge for any host call (state access is far costlier than an
/// arithmetic op).
const CU_HOST_CALL: u64 = 25;
/// Extra surcharge for generating an inclusion proof (a proven read walks the
/// sparse Merkle path — much heavier than a plain read).
const CU_PROVE: u64 = 100;
/// Maximum operand-stack depth (mirrors the EVM's 1024). Bounds memory even
/// though the compute budget already bounds iteration count.
const STACK_LIMIT: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("stack underflow at pc {0}")]
    StackUnderflow(usize),
    #[error("stack overflow at pc {0} (limit {STACK_LIMIT})")]
    StackOverflow(usize),
    #[error("jump at pc {pc} targets out-of-range instruction {target}")]
    InvalidJump { pc: usize, target: usize },
    #[error("compute budget exhausted (limit {0} CU)")]
    OutOfCompute(u64),
    #[error("host call failed: {0}")]
    Host(String),
    #[error("no verified foreign state for chain {chain_id} at slot (absent or unproven)")]
    EthStateUnavailable { chain_id: u64 },
    #[error("foreign state value does not fit in 64 bits (would truncate)")]
    EthStateTooWide,
    #[error("invalid program: {0}")]
    InvalidProgram(String),
}

/// A verifiable read returned by [`Host::table_read_proven`]: the value plus an
/// opaque inclusion proof and the state root it verifies against. The VM treats
/// `proof` as opaque bytes (so the interpreter stays decoupled from the exact
/// proof format) — it only *meters* them; a stateless verifier re-checks the
/// proof against `root` off the hot path.
#[derive(Clone, Debug)]
pub struct ProvenValue {
    pub value: Vec<u8>,
    pub proof: Vec<u8>,
    pub root: Hash,
}

/// The environment the VM runs inside: the node exposes tables + streams.
/// Data-meter charging happens in the VM (so costs are consensus-identical),
/// while the host performs the actual state effects.
pub trait Host {
    fn table_insert(&mut self, table: TableId, key: Vec<u8>, value: Vec<u8>) -> Result<(), String>;
    fn table_read(&mut self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
    /// Read `key` from `table` **with** an inclusion proof (verifiable /
    /// stateless read). `None` if the key is absent.
    fn table_read_proven(
        &mut self,
        table: TableId,
        key: &[u8],
    ) -> Result<Option<ProvenValue>, String>;
    /// Emit a record on a node-owned stream (contract-originated data).
    fn stream_emit(&mut self, payload: Vec<u8>) -> Result<(), String>;
    /// Read a **verified** foreign-chain storage word.
    ///
    /// `None` means "not verified on this chain", which the VM turns into a
    /// trap rather than a zero — see [`Instr::LoadEthState`].
    fn eth_state_read(
        &mut self,
        chain_id: u64,
        address: [u8; 20],
        slot: [u8; 32],
    ) -> Result<Option<[u8; 32]>, String>;
}

/// Bootstrap instruction set: a tiny stack machine with arithmetic, comparison,
/// control flow, and data-native host calls — enough to express real
/// "compute → branch/loop → write → prove" programs for the demo and for
/// differential tests against the future RISC-V core.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Instr {
    // ── stack ──
    /// Push a 64-bit constant.
    Push(u64),
    /// Discard the top value.
    Pop,
    /// Duplicate the top value.
    Dup,
    /// Swap the top two values.
    Swap,

    // ── arithmetic (pop b, pop a, push a∘b; wrapping) ──
    Add,
    Sub,
    Mul,
    /// Integer division; division by zero yields 0 (EVM semantics).
    Div,
    /// Integer remainder; mod by zero yields 0 (EVM semantics).
    Mod,

    // ── comparison (push 1 if true else 0) ──
    Lt,
    Gt,
    Eq,

    // ── control flow (targets are instruction indices) ──
    /// Unconditional jump.
    Jump(usize),
    /// Pop a condition; jump if it is non-zero.
    JumpIf(usize),

    // ── data-native host calls ──
    /// Pop value; insert into `table` at `key` (LE-encoded value).
    /// Charges the data meter for key+value bytes.
    StoreTable {
        table: TableId,
        key: Vec<u8>,
    },
    /// Read `key` from `table`; push its first 8 bytes as u64 (0 if absent).
    LoadTable {
        table: TableId,
        key: Vec<u8>,
    },
    /// Proven read of `key` from `table`; push its value as u64 (0 if absent).
    /// Charges a proof-generation compute surcharge and the proof's data bytes.
    LoadTableProven {
        table: TableId,
        key: Vec<u8>,
    },
    /// Pop value; emit as a stream record payload (LE bytes).
    /// Charges the data meter for payload bytes.
    EmitStream,
    /// Push a **proven** foreign-chain storage word.
    ///
    /// Unlike [`Instr::LoadTable`], an unavailable value **traps** instead of
    /// pushing zero. That asymmetry is deliberate: a contract asking "what is
    /// this Ethereum balance?" must never be silently told "zero" because the
    /// proof was missing — a fact that has not been verified is not a fact.
    /// Values wider than 64 bits also trap rather than silently truncating.
    LoadEthState {
        chain_id: u64,
        address: [u8; 20],
        slot: [u8; 32],
    },

    /// Stop cleanly.
    Halt,
}

/// Execution result. `meter` is **always** populated (fees are charged whether
/// or not the program trapped). `trap` is `None` on a clean halt/fall-off-end,
/// or `Some(err)` if execution aborted — in which case any state effects
/// already applied by the host persist (deterministically on every node); a
/// journaling/rollback host is a tracked follow-up.
#[derive(Debug)]
pub struct ExecResult {
    pub stack: Vec<u64>,
    pub meter: DualMeter,
    pub trap: Option<VmError>,
}

impl ExecResult {
    pub fn is_ok(&self) -> bool {
        self.trap.is_none()
    }
    pub fn top(&self) -> Option<u64> {
        self.stack.last().copied()
    }
}

/// Control-flow outcome of a single instruction.
enum Flow {
    Next,
    JumpTo(usize),
    Halt,
}

/// The interpreter.
pub struct Vm {
    compute_limit: u64,
}

impl Vm {
    pub fn new(compute_limit: u64) -> Self {
        Self { compute_limit }
    }

    /// Run a program to completion (or to a trap) under the compute budget.
    /// Never panics and never returns an outer `Err`: a fault becomes
    /// `ExecResult { trap: Some(_), .. }` with the meter charged up to the
    /// fault, so the caller always settles fees.
    pub fn execute<H: Host>(&self, program: &[Instr], host: &mut H) -> ExecResult {
        let mut stack: Vec<u64> = Vec::with_capacity(16);
        let mut meter = DualMeter::default();
        let len = program.len();
        let mut pc = 0usize;

        let trap = loop {
            if pc >= len {
                break None; // fell off the end == clean stop
            }
            meter.tick_compute(CU_PER_INSTRUCTION);
            if meter.compute_units > self.compute_limit {
                break Some(VmError::OutOfCompute(self.compute_limit));
            }
            match step(
                &program[pc],
                pc,
                &mut stack,
                &mut meter,
                host,
                self.compute_limit,
                len,
            ) {
                Ok(Flow::Next) => pc += 1,
                Ok(Flow::JumpTo(t)) => pc = t,
                Ok(Flow::Halt) => break None,
                Err(e) => break Some(e),
            }
        };

        ExecResult { stack, meter, trap }
    }

    /// EVM-compatibility mounting point.
    ///
    /// Today: lowers a call descriptor `(to, selector, args)` to an equivalent
    /// Talon program (sum the args, store under the selector key) and executes
    /// it, so EVM-shaped traffic and native Talon flow through one metering +
    /// host path. The transpiler replaces the body without changing this
    /// signature or the fee semantics wallets/relayers observe.
    pub fn call_evm<H: Host>(
        &self,
        host: &mut H,
        to: Hash,
        selector: [u8; 4],
        args: &[u64],
    ) -> ExecResult {
        let table = TableId(to);
        let key = selector.to_vec();
        let mut program: Vec<Instr> = Vec::with_capacity(args.len() * 2 + 3);
        program.push(Instr::Push(0));
        for a in args {
            program.push(Instr::Push(*a));
            program.push(Instr::Add);
        }
        program.push(Instr::StoreTable { table, key });
        program.push(Instr::Halt);
        self.execute(&program, host)
    }
}

/// Execute one instruction. Returns the control-flow outcome or a trap. Compute
/// surcharges for host calls are checked against `limit` *before* the host
/// effect, so an out-of-gas program never applies a partial host op.
fn step<H: Host>(
    instr: &Instr,
    pc: usize,
    stack: &mut Vec<u64>,
    meter: &mut DualMeter,
    host: &mut H,
    limit: u64,
    len: usize,
) -> Result<Flow, VmError> {
    match instr {
        // ── stack ──
        Instr::Push(v) => {
            push(stack, *v, pc)?;
        }
        Instr::Pop => {
            pop(stack, pc)?;
        }
        Instr::Dup => {
            let top = *stack.last().ok_or(VmError::StackUnderflow(pc))?;
            push(stack, top, pc)?;
        }
        Instr::Swap => {
            let n = stack.len();
            if n < 2 {
                return Err(VmError::StackUnderflow(pc));
            }
            stack.swap(n - 1, n - 2);
        }

        // ── arithmetic ──
        Instr::Add => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, a.wrapping_add(b), pc)?;
        }
        Instr::Sub => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, a.wrapping_sub(b), pc)?;
        }
        Instr::Mul => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, a.wrapping_mul(b), pc)?;
        }
        Instr::Div => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, a.checked_div(b).unwrap_or(0), pc)?;
        }
        Instr::Mod => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, a.checked_rem(b).unwrap_or(0), pc)?;
        }

        // ── comparison ──
        Instr::Lt => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, (a < b) as u64, pc)?;
        }
        Instr::Gt => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, (a > b) as u64, pc)?;
        }
        Instr::Eq => {
            let (b, a) = pop2(stack, pc)?;
            push(stack, (a == b) as u64, pc)?;
        }

        // ── control flow ──
        Instr::Jump(target) => {
            if *target >= len {
                return Err(VmError::InvalidJump {
                    pc,
                    target: *target,
                });
            }
            return Ok(Flow::JumpTo(*target));
        }
        Instr::JumpIf(target) => {
            let cond = pop(stack, pc)?;
            if cond != 0 {
                if *target >= len {
                    return Err(VmError::InvalidJump {
                        pc,
                        target: *target,
                    });
                }
                return Ok(Flow::JumpTo(*target));
            }
        }

        // ── host calls ──
        Instr::StoreTable { table, key } => {
            charge_host(meter, CU_HOST_CALL, limit)?;
            let v = pop(stack, pc)?;
            let value = v.to_le_bytes().to_vec();
            meter.tick_data((key.len() + value.len()) as u64);
            host.table_insert(*table, key.clone(), value)
                .map_err(VmError::Host)?;
        }
        Instr::LoadTable { table, key } => {
            charge_host(meter, CU_HOST_CALL, limit)?;
            let bytes = host.table_read(*table, key).map_err(VmError::Host)?;
            push(stack, as_u64(bytes.as_deref()), pc)?;
        }
        Instr::LoadTableProven { table, key } => {
            charge_host(meter, CU_HOST_CALL + CU_PROVE, limit)?;
            match host.table_read_proven(*table, key).map_err(VmError::Host)? {
                Some(pv) => {
                    // The proof is real, data-priced bytes — the honest cost of
                    // a verifiable read.
                    meter.tick_data((key.len() + pv.value.len() + pv.proof.len()) as u64);
                    push(stack, as_u64(Some(&pv.value)), pc)?;
                }
                None => {
                    meter.tick_data(key.len() as u64);
                    push(stack, 0, pc)?;
                }
            }
        }
        Instr::LoadEthState {
            chain_id,
            address,
            slot,
        } => {
            charge_host(meter, CU_HOST_CALL, limit)?;
            match host
                .eth_state_read(*chain_id, *address, *slot)
                .map_err(VmError::Host)?
            {
                Some(word) => {
                    meter.tick_data(word.len() as u64);
                    // Big-endian u256 → u64, refusing anything that would lose
                    // information rather than quietly truncating it.
                    if word[..24].iter().any(|b| *b != 0) {
                        return Err(VmError::EthStateTooWide);
                    }
                    let mut low = [0u8; 8];
                    low.copy_from_slice(&word[24..]);
                    push(stack, u64::from_be_bytes(low), pc)?;
                }
                None => {
                    return Err(VmError::EthStateUnavailable {
                        chain_id: *chain_id,
                    })
                }
            }
        }
        Instr::EmitStream => {
            charge_host(meter, CU_HOST_CALL, limit)?;
            let v = pop(stack, pc)?;
            let payload = v.to_le_bytes().to_vec();
            meter.tick_data(payload.len() as u64);
            host.stream_emit(payload).map_err(VmError::Host)?;
        }

        Instr::Halt => return Ok(Flow::Halt),
    }
    Ok(Flow::Next)
}

/// Charge a host-call compute surcharge and fail *before* the effect if it
/// pushes the program over budget.
fn charge_host(meter: &mut DualMeter, units: u64, limit: u64) -> Result<(), VmError> {
    meter.tick_compute(units);
    if meter.compute_units > limit {
        return Err(VmError::OutOfCompute(limit));
    }
    Ok(())
}

fn push(stack: &mut Vec<u64>, v: u64, pc: usize) -> Result<(), VmError> {
    if stack.len() >= STACK_LIMIT {
        return Err(VmError::StackOverflow(pc));
    }
    stack.push(v);
    Ok(())
}

fn pop(stack: &mut Vec<u64>, pc: usize) -> Result<u64, VmError> {
    stack.pop().ok_or(VmError::StackUnderflow(pc))
}

/// Pop two: returns `(top, second)` so callers read `a ∘ b` as `second ∘ top`.
fn pop2(stack: &mut Vec<u64>, pc: usize) -> Result<(u64, u64), VmError> {
    let b = pop(stack, pc)?;
    let a = pop(stack, pc)?;
    Ok((b, a))
}

/// First 8 little-endian bytes as u64, or 0 if absent/short.
fn as_u64(bytes: Option<&[u8]>) -> u64 {
    match bytes {
        Some(b) if b.len() >= 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockHost {
        eth_state: HashMap<[u8; 32], [u8; 32]>,
        tables: HashMap<(TableId, Vec<u8>), Vec<u8>>,
        emitted: Vec<Vec<u8>>,
        /// Bytes returned as the fabricated proof for a proven read.
        proof_len: usize,
        fail_next_insert: bool,
    }

    impl Host for MockHost {
        fn table_insert(&mut self, t: TableId, k: Vec<u8>, v: Vec<u8>) -> Result<(), String> {
            if self.fail_next_insert {
                return Err("boom".into());
            }
            self.tables.insert((t, k), v);
            Ok(())
        }
        fn table_read(&mut self, t: TableId, k: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(self.tables.get(&(t, k.to_vec())).cloned())
        }
        fn table_read_proven(
            &mut self,
            t: TableId,
            k: &[u8],
        ) -> Result<Option<ProvenValue>, String> {
            Ok(self
                .tables
                .get(&(t, k.to_vec()))
                .cloned()
                .map(|value| ProvenValue {
                    value,
                    proof: vec![0u8; self.proof_len],
                    root: Hash::ZERO,
                }))
        }
        fn stream_emit(&mut self, p: Vec<u8>) -> Result<(), String> {
            self.emitted.push(p);
            Ok(())
        }
        fn eth_state_read(
            &mut self,
            _chain_id: u64,
            _address: [u8; 20],
            slot: [u8; 32],
        ) -> Result<Option<[u8; 32]>, String> {
            Ok(self.eth_state.get(&slot).copied())
        }
    }

    fn read_u64(host: &MockHost, t: TableId, k: &[u8]) -> Option<u64> {
        host.tables.get(&(t, k.to_vec())).map(|b| as_u64(Some(b)))
    }

    #[test]
    fn metered_store_and_emit() {
        let vm = Vm::new(10_000);
        let mut host = MockHost::default();
        let t = TableId::named("t");
        let program = vec![
            Instr::Push(20),
            Instr::Push(22),
            Instr::Add,
            Instr::StoreTable {
                table: t,
                key: b"answer".to_vec(),
            },
            Instr::LoadTable {
                table: t,
                key: b"answer".to_vec(),
            },
            Instr::EmitStream,
            Instr::Halt,
        ];
        let res = vm.execute(&program, &mut host);
        assert!(res.is_ok());
        assert_eq!(host.emitted, vec![42u64.to_le_bytes().to_vec()]);
        assert!(res.meter.compute_units > 0);
        // data meter: store("answer"=6 + 8) + emit(8)
        assert_eq!(res.meter.data_bytes, (6 + 8 + 8) as u64);
    }

    #[test]
    fn arithmetic_and_div_by_zero() {
        let vm = Vm::new(10_000);
        let mut host = MockHost::default();
        // (100 - 58) = 42, 42 / 6 = 7, 7 % 4 = 3
        let prog = vec![
            Instr::Push(100),
            Instr::Push(58),
            Instr::Sub,
            Instr::Push(6),
            Instr::Div,
            Instr::Push(4),
            Instr::Mod,
            Instr::Halt,
        ];
        assert_eq!(vm.execute(&prog, &mut host).top(), Some(3));
        // div by zero → 0, mod by zero → 0
        let z = vec![Instr::Push(9), Instr::Push(0), Instr::Div, Instr::Halt];
        assert_eq!(vm.execute(&z, &mut host).top(), Some(0));
    }

    #[test]
    fn stack_ops() {
        let vm = Vm::new(10_000);
        let mut host = MockHost::default();
        // push 7, dup -> [7,7], push 3, swap -> [7,3,7], pop -> [7,3], sub -> 4
        let prog = vec![
            Instr::Push(7),
            Instr::Dup,
            Instr::Push(3),
            Instr::Swap,
            Instr::Pop,
            Instr::Sub,
            Instr::Halt,
        ];
        assert_eq!(vm.execute(&prog, &mut host).top(), Some(4));
    }

    /// Loop: sum 1..=N into a table cell, counter on the stack. Exercises Dup,
    /// JumpIf, Jump, Add, Sub, and load/store in a loop.
    fn sum_loop(t: TableId, n: u64) -> Vec<Instr> {
        // 0: Push 0
        // 1: StoreTable sum          ; sum = 0
        // 2: Push n                   ; [i]
        // 3: Dup                      ; [i, i]         (loop test)
        // 4: JumpIf 6                 ; if i != 0 -> body(6); else fall to 5
        // 5: Jump 13                  ; -> END (Halt)
        // 6: Dup                      ; [i, i]         (body)
        // 7: LoadTable sum            ; [i, i, sum]
        // 8: Add                      ; [i, i+sum]
        // 9: StoreTable sum           ; [i]
        // 10: Push 1                  ; [i, 1]
        // 11: Sub                     ; [i-1]
        // 12: Jump 3                  ; loop back to the test
        // 13: Halt                    ; END
        vec![
            Instr::Push(0), // 0
            Instr::StoreTable {
                table: t,
                key: b"sum".to_vec(),
            }, // 1
            Instr::Push(n), // 2
            Instr::Dup,     // 3
            Instr::JumpIf(6), // 4
            Instr::Jump(13), // 5
            Instr::Dup,     // 6
            Instr::LoadTable {
                table: t,
                key: b"sum".to_vec(),
            }, // 7
            Instr::Add,     // 8
            Instr::StoreTable {
                table: t,
                key: b"sum".to_vec(),
            }, // 9
            Instr::Push(1), // 10
            Instr::Sub,     // 11
            Instr::Jump(3), // 12
            Instr::Halt,    // 13 (END)
        ]
    }

    #[test]
    fn control_flow_loop_sums() {
        let vm = Vm::new(1_000_000);
        let mut host = MockHost::default();
        let t = TableId::named("acc");
        let res = vm.execute(&sum_loop(t, 10), &mut host);
        assert!(res.is_ok(), "trap: {:?}", res.trap);
        assert_eq!(read_u64(&host, t, b"sum"), Some(55)); // 1+..+10
                                                          // 10 iterations really ran (compute grew well past the ~14 instrs).
        assert!(res.meter.compute_units > 100, "loop should cost real CU");
    }

    #[test]
    fn conditional_branch() {
        let vm = Vm::new(10_000);
        let t = TableId::named("c");
        // if a > b { store 111 } else { store 222 }
        let prog = |a: u64, b: u64| {
            vec![
                Instr::Push(a),   // 0
                Instr::Push(b),   // 1
                Instr::Gt,        // 2  -> 1 if a>b
                Instr::JumpIf(7), // 3
                Instr::Push(222), // 4 (else)
                Instr::StoreTable {
                    table: t,
                    key: b"r".to_vec(),
                }, // 5
                Instr::Jump(9),   // 6
                Instr::Push(111), // 7 (then)
                Instr::StoreTable {
                    table: t,
                    key: b"r".to_vec(),
                }, // 8
                Instr::Halt,      // 9
            ]
        };
        let mut h1 = MockHost::default();
        vm.execute(&prog(5, 3), &mut h1);
        assert_eq!(read_u64(&h1, t, b"r"), Some(111));
        let mut h2 = MockHost::default();
        vm.execute(&prog(2, 8), &mut h2);
        assert_eq!(read_u64(&h2, t, b"r"), Some(222));
    }

    #[test]
    fn infinite_loop_halts_on_gas() {
        let vm = Vm::new(500);
        let mut host = MockHost::default();
        let prog = vec![Instr::Jump(0)]; // spin forever
        let res = vm.execute(&prog, &mut host);
        assert!(matches!(res.trap, Some(VmError::OutOfCompute(500))));
        assert!(res.meter.compute_units >= 500, "charged up to the budget");
    }

    #[test]
    fn invalid_jump_traps() {
        let vm = Vm::new(10_000);
        let mut host = MockHost::default();
        let res = vm.execute(&[Instr::Jump(99), Instr::Halt], &mut host);
        assert!(matches!(
            res.trap,
            Some(VmError::InvalidJump { target: 99, .. })
        ));
    }

    #[test]
    fn stack_overflow_traps() {
        let vm = Vm::new(1_000_000);
        let mut host = MockHost::default();
        // Push once, then Dup in a tight loop until the stack cap is hit.
        let prog = vec![Instr::Push(1), Instr::Dup, Instr::Jump(1)];
        let res = vm.execute(&prog, &mut host);
        assert!(matches!(res.trap, Some(VmError::StackOverflow(_))));
    }

    #[test]
    fn out_of_compute() {
        let vm = Vm::new(2);
        let mut host = MockHost::default();
        let program = vec![Instr::Push(1), Instr::Push(2), Instr::Add, Instr::Halt];
        let res = vm.execute(&program, &mut host);
        assert!(matches!(res.trap, Some(VmError::OutOfCompute(2))));
    }

    #[test]
    fn gas_charged_on_trap() {
        // A store (metered) followed by a bad jump: the meter must reflect the
        // work already done, proving failure isn't free.
        let vm = Vm::new(10_000);
        let mut host = MockHost::default();
        let t = TableId::named("g");
        let prog = vec![
            Instr::Push(5),
            Instr::StoreTable {
                table: t,
                key: b"k".to_vec(),
            },
            Instr::Jump(999), // trap
        ];
        let res = vm.execute(&prog, &mut host);
        assert!(res.trap.is_some());
        assert!(
            res.meter.compute_units >= CU_HOST_CALL,
            "host work charged despite trap"
        );
        assert_eq!(
            res.meter.data_bytes,
            (1 + 8) as u64,
            "store bytes charged despite trap"
        );
    }

    #[test]
    fn host_error_traps() {
        let vm = Vm::new(10_000);
        let mut host = MockHost {
            fail_next_insert: true,
            ..Default::default()
        };
        let t = TableId::named("h");
        let prog = vec![
            Instr::Push(1),
            Instr::StoreTable {
                table: t,
                key: b"k".to_vec(),
            },
        ];
        let res = vm.execute(&prog, &mut host);
        assert!(matches!(res.trap, Some(VmError::Host(_))));
    }

    #[test]
    fn proven_read_meters_proof_bytes() {
        let vm = Vm::new(10_000);
        let mut host = MockHost {
            proof_len: 300,
            ..Default::default()
        };
        let t = TableId::named("p");
        // seed a value, then proven-read it back
        let prog = vec![
            Instr::Push(1234),
            Instr::StoreTable {
                table: t,
                key: b"k".to_vec(),
            },
            Instr::LoadTableProven {
                table: t,
                key: b"k".to_vec(),
            },
            Instr::Halt,
        ];
        let res = vm.execute(&prog, &mut host);
        assert!(res.is_ok());
        assert_eq!(res.top(), Some(1234), "proven read pushes the value");
        // proof-gen compute surcharge is reflected
        assert!(res.meter.compute_units >= CU_PROVE);
        // data: store(1+8) + proven read(key 1 + value 8 + proof 300)
        assert_eq!(res.meter.data_bytes, (1 + 8) + (1 + 8 + 300));
    }

    #[test]
    fn call_evm_flows_through_metering() {
        let vm = Vm::new(10_000);
        let mut host = MockHost::default();
        let to = Hash::digest(b"contract");
        let res = vm.call_evm(&mut host, to, [1, 2, 3, 4], &[10, 20, 12]);
        assert!(res.is_ok());
        assert_eq!(read_u64(&host, TableId(to), &[1, 2, 3, 4]), Some(42));
        assert!(res.meter.compute_units > 0);
    }
}

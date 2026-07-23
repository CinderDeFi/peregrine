/**
 * Peregrine Explorer — verification-first.
 *
 * The explorer contains no cryptography of its own. It drives the real
 * `@peregrine/sdk` (bundled at ./vendor/peregrine-sdk.js): the transport moves
 * bytes, and `verifyProvenRead` re-checks every value against the store root in
 * this page. A hostile or buggy gateway can withhold or stall, but a tampered
 * proof fails the local check — which is the whole point of shipping proofs.
 *
 * Two transports, same `Transport` interface:
 *   • HttpTransport  → a live `peregrine gateway`
 *   • DemoTransport  → bundled real Rust-generated proofs, for GitHub Pages
 *
 * Mode selection (see the config block below):
 *   • `?gateway=URL` → live, against that gateway;
 *   • `?demo=1`      → offline demo (explicit — always works with no live node);
 *   • neither        → live, defaulting to the public testnet gateway.
 * The default gateway is a public **unaudited** testnet holding no real value.
 */
import {
  PeregrineClient,
  HttpTransport,
  verifyProvenRead,
  provenReadFromJson,
  tableId,
  fromHex,
  toHex,
  verifySelectiveDisclosure,
  selectiveDisclosureFromJson,
  gate,
  decodeFlag,
} from "./vendor/peregrine-sdk.js";
import { DemoTransport } from "./demo-transport.js";

// ── configuration ────────────────────────────────────────────────────────────

// Public testnet gateway used when no `?gateway=` is given and demo is not
// requested. It is an unaudited testnet with no real value; it is a public
// endpoint URL, not a secret. Override with `?gateway=<url>` for your own node.
const DEFAULT_GATEWAY = "http://37.27.182.133:8081/rpc";

const params = new URLSearchParams(location.search);
// Precedence: explicit `?demo` wins (offline, always works with no live node);
// otherwise `?gateway=URL`; otherwise the default public testnet gateway (live).
const gatewayParam = params.get("gateway"); // e.g. http://localhost:8080/rpc
const mode = params.has("demo") ? "demo" : "live";
const gatewayUrl = mode === "live" ? gatewayParam || DEFAULT_GATEWAY : null;

// ── state ────────────────────────────────────────────────────────────────────

const state = {
  client: null,
  catalog: [], // { table, key, label, category }
  root: null, // hex string
  tree: null,
  commits: [], // { root, height, at }
  height: 0,
  poll: 0,
  filter: "all",
  tamper: false,
  down: false,
};

const $ = (id) => document.getElementById(id);
const short = (hex, n = 10) => (hex ? `${hex.slice(0, n)}…${hex.slice(-6)}` : "—");

/** Decode a committed value: u64 little-endian when 8+ bytes, else 0x-hex. */
function renderValue(bytes) {
  if (bytes.length >= 8) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
    return v.toString();
  }
  return "0x" + toHex(bytes);
}

// ── boot ─────────────────────────────────────────────────────────────────────

async function boot() {
  let transport;
  if (mode === "live") {
    transport = new HttpTransport(gatewayUrl);
    const isDefault = gatewayUrl === DEFAULT_GATEWAY;
    $("banner").className = "banner live";
    $("banner").innerHTML =
      `<b>Live.</b> Connected to a gateway at <code>${gatewayUrl}</code>` +
      (isDefault ? ` — the public <b>peregrine-testnet</b> (chain id 1). ` : `. `) +
      `Every value below is proven by that node and verified here against the store root. ` +
      (isDefault
        ? `This is an <b>unaudited</b> public testnet holding <b>no real value</b>. `
        : ``) +
      `<a href="?demo=1">View the offline demo</a> instead.`;
  } else {
    const data = await (await fetch("./demo-data.json")).json();
    transport = new DemoTransport(data);
    state.catalog = data.catalog;
    state.demoData = data;
    $("banner").innerHTML =
      `<b>Offline demo.</b> ${data.note} ` +
      `<a href="?">Connect to the public testnet</a> (live, unaudited, no real value), ` +
      `or point this at your own node with <code>?gateway=http://localhost:8080/rpc</code>.`;
  }
  state.client = new PeregrineClient(transport);

  // In live mode we have no catalog endpoint (the node exposes only proofs), so
  // watch a sensible default set. Users can reach anything else via Search.
  if (mode === "live" && state.catalog.length === 0) {
    state.catalog = defaultLiveCatalog();
  }

  renderWatchSkeleton();
  wireUI();
  renderDisclosureCompliance();
  tick(); // immediate first paint
  setInterval(tick, 1000);
}

// ── selective disclosure & compliance (demo fixtures, verified in-browser) ────

const STATUS_NAMES = ["Unverified", "Pending", "Verified", "Rejected"];

function decodeField(bytes) {
  if (bytes.length && bytes.every((b) => b >= 0x20 && b < 0x7f)) {
    return new TextDecoder().decode(bytes);
  }
  return "0x" + toHex(bytes);
}

function renderDisclosureCompliance() {
  const data = state.demoData;
  if (!data || (!data.disclosure && !data.compliance)) return;
  $("disclosure").style.display = "";

  if (data.disclosure) {
    const d = data.disclosure;
    const disc = selectiveDisclosureFromJson(d);
    const ok = verifySelectiveDisclosure(disc, fromHex(d.storeRoot));
    const revealed = new Map(disc.reveals.map((r) => [r.index, r.value]));
    let rows = "";
    for (let i = 0; i < d.arity; i++) {
      if (revealed.has(i)) {
        rows += `<div class="field"><span class="idx">#${i}</span><span class="fv">${escapeHtml(decodeField(revealed.get(i)))}</span><span class="badge ok">✓ revealed</span></div>`;
      } else {
        rows += `<div class="field"><span class="idx">#${i}</span><span class="fv hidden">•••• hidden</span><span class="badge absent">— not disclosed</span></div>`;
      }
    }
    $("discOut").innerHTML =
      `<div class="headline"><span class="badge ${ok ? "ok" : "bad"}">${ok ? "✓ verified against the store root" : "✗ failed"}</span></div>` +
      `<div class="kv">field commitment ${toHex(disc.read.value)}</div>` +
      `<div style="margin-top:10px">${rows}</div>` +
      `<p class="hint" style="margin:10px 0 0">${disc.reveals.length} of ${d.arity} fields revealed; the rest are committed but never sent — a KYC record proving residency and date of birth without exposing name or passport number.</p>`;
  }

  if (data.compliance) {
    const c = data.compliance;
    const read = provenReadFromJson(c.read);
    const root = fromHex(c.storeRoot);
    const policy = { attester: fromHex(c.attester), scheme: c.scheme };
    const subject = fromHex(c.subject);
    const now = gate(policy, subject, read, root, c.nowRound);
    const expired = gate(policy, subject, read, root, c.expiredNowRound);
    const wrong = gate({ attester: fromHex(c.otherAttester) }, subject, read, root, c.nowRound);
    const flag = decodeFlag(read.value) ?? {};
    const statusName = STATUS_NAMES[flag.status] ?? "?";
    $("compOut").innerHTML =
      `<div class="headline"><span class="badge ${now.ok ? "ok" : "bad"}">${now.ok ? "✓ compliant" : "✗ " + now.reason}</span></div>` +
      `<div class="kv">subject   ${c.subject.slice(0, 22)}…</div>` +
      `<div class="kv">attester  ${c.attester.slice(0, 22)}…</div>` +
      `<div class="kv">flag      ${statusName} · scheme ${flag.scheme} · expires round ${flag.expiresRound}</div>` +
      `<div style="margin-top:8px" class="field"><span class="idx"></span><span class="fv">at round ${c.nowRound}</span><span class="badge ${now.ok ? "ok" : "bad"}">${now.ok ? "✓ passes gate" : "✗"}</span></div>` +
      `<div class="field"><span class="idx"></span><span class="fv">at round ${c.expiredNowRound}</span><span class="badge ${expired.ok ? "ok" : "bad"}">${expired.ok ? "✓" : "✗ expired"}</span></div>` +
      `<div class="field"><span class="idx"></span><span class="fv">a different attester</span><span class="badge ${wrong.ok ? "ok" : "bad"}">${wrong.ok ? "✓" : "✗ wrong cell"}</span></div>` +
      `<p class="hint" style="margin:10px 0 0">The gate reads the committed flag against the store root — no signature re-check, no global authority. Requiring another attester reads a different, empty cell.</p>`;
  }
}

/** A few well-known keys to watch on a fresh devnet (see `peregrine demo`). */
function defaultLiveCatalog() {
  const ticks = toHex(tableId("sys.stream_ticks"));
  const answers = toHex(tableId("sdk.contract"));
  const tickKey = (i) => {
    const k = new Uint8Array(40);
    k.fill(7, 0, 32);
    const dv = new DataView(k.buffer);
    dv.setBigUint64(32, BigInt(i), false); // big-endian index
    return toHex(k);
  };
  return [
    { table: answers, key: toHex(new TextEncoder().encode("sum")), label: "sdk.contract['sum']", category: "table" },
    { table: ticks, key: tickKey(0), label: "stream tick #0", category: "stream" },
    { table: ticks, key: tickKey(1), label: "stream tick #1", category: "stream" },
  ];
}

// ── polling ──────────────────────────────────────────────────────────────────

async function tick() {
  try {
    const root = toHex(await state.client.storeRoot());
    state.down = false;
    state.poll += 1;
    if (root !== state.root) {
      state.root = root;
      state.height += 1;
      state.commits.unshift({ root, height: state.height, at: new Date() });
      state.commits = state.commits.slice(0, 12);
      flash($("rootVal"));
    }
    renderHead();
    renderCommits();
    await refreshWatched();
  } catch (e) {
    state.down = true;
    renderHead();
  }
  renderStatus();
}

async function refreshWatched() {
  const rootBytes = fromHex(state.root);
  await Promise.all(
    state.catalog.map(async (entry) => {
      const cell = document.querySelector(`[data-row="${entry.table}:${entry.key}"]`);
      if (!cell) return;
      try {
        const resp = await state.client.proveRead(entry.table, entry.key);
        if (resp === null) return setRow(cell, "—", "absent", "— absent");
        const ok = verifyProvenRead(resp, rootBytes);
        if (ok && resp.treeVersion !== state.tree) {
          state.tree = resp.treeVersion;
          $("treeVal").textContent = state.tree;
        }
        setRow(cell, renderValue(resp.value), ok ? "ok" : "bad", ok ? "✓ verified" : "✗ FORGED");
      } catch {
        setRow(cell, "—", "pending", "· error");
      }
    }),
  );
}

// ── rendering ────────────────────────────────────────────────────────────────

function renderStatus() {
  const led = $("led");
  const txt = $("statusText");
  if (state.down) {
    led.className = "led down";
    txt.textContent = mode === "live" ? "gateway unreachable" : "demo error";
  } else if (mode === "live") {
    led.className = "led live";
    txt.textContent = "live · gateway";
  } else {
    led.className = "led demo";
    txt.textContent = "offline demo";
  }
}

function renderHead() {
  $("rootVal").textContent = state.down ? "unreachable" : state.root ?? "—";
  $("treeVal").textContent = state.tree ?? "—";
  $("heightVal").textContent = state.height;
  $("pollVal").textContent = state.poll;
}

function renderCommits() {
  const el = $("commits");
  if (state.commits.length === 0) {
    el.innerHTML = `<div class="empty">waiting for the first committed root…</div>`;
    return;
  }
  el.innerHTML = state.commits
    .map(
      (c, i) => `<div class="commit${i === 0 ? " new" : ""}">
        <span class="h">#${c.height}</span>
        <span class="r">${c.root}</span>
        <span class="t">${timeAgo(c.at)}</span>
      </div>`,
    )
    .join("");
}

function renderWatchSkeleton() {
  const el = $("watchRows");
  if (state.catalog.length === 0) {
    el.innerHTML = `<div class="empty">nothing to watch — use Search below.</div>`;
    return;
  }
  el.innerHTML = state.catalog
    .map(
      (e) => `<div class="row" data-cat="${e.category}" data-key="${e.table}:${e.key}">
        <div>
          <div class="label">${escapeHtml(e.label)} <span class="cat">${e.category}</span></div>
          <div class="kv">${short(e.table, 14)} · key ${short(e.key, 10)}</div>
        </div>
        <div class="value" data-row="${e.table}:${e.key}"><span class="v">—</span></div>
        <div><span class="badge pending" data-badge="${e.table}:${e.key}">· polling</span></div>
      </div>`,
    )
    .join("");
  applyFilter();
}

function setRow(valueCell, value, badgeClass, badgeText) {
  valueCell.querySelector(".v").textContent = value;
  const key = valueCell.getAttribute("data-row");
  const badge = document.querySelector(`[data-badge="${key}"]`);
  if (badge) {
    badge.className = `badge ${badgeClass}`;
    badge.textContent = badgeText;
  }
}

function applyFilter() {
  document.querySelectorAll("#watchRows .row").forEach((r) => {
    const show = state.filter === "all" || r.getAttribute("data-cat") === state.filter;
    r.style.display = show ? "" : "none";
  });
}

// ── search ───────────────────────────────────────────────────────────────────

function parseTable(s) {
  s = s.trim();
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(s)) return s.replace(/^0x/, "").toLowerCase();
  return toHex(tableId(s)); // treat as a table name
}
function parseKey(s) {
  s = s.trim();
  if (s.startsWith("hex:")) return s.slice(4).toLowerCase();
  return toHex(new TextEncoder().encode(s));
}

async function runSearch() {
  const raw = $("q").value.trim();
  const out = $("searchOut");
  const sep = raw.lastIndexOf(":");
  if (sep < 1) {
    out.innerHTML = `<div class="empty">enter <code>table:key</code> — e.g. <code>contract.answers:sum</code></div>`;
    return;
  }
  const tableStr = raw.slice(0, sep);
  const keyStr = raw.slice(sep + 1);
  let table, key;
  try {
    table = parseTable(tableStr);
    key = parseKey(keyStr);
  } catch {
    out.innerHTML = `<div class="empty">could not parse that table or key.</div>`;
    return;
  }

  out.innerHTML = `<div class="result"><div class="empty">proving…</div></div>`;
  try {
    const resp = await state.client.proveRead(table, key);
    if (resp === null) {
      out.innerHTML = `<div class="result">
        <div class="headline"><span class="badge absent">— absent</span></div>
        <div class="kv">table ${table}</div><div class="kv">key   ${key}</div>
        <p class="hint" style="margin:8px 0 0">No value under this key. In Peregrine, absence is an explicit result — never a silent zero.</p>
      </div>`;
      return;
    }
    const rootBytes = fromHex(state.root);
    let read = resp;
    let tampered = false;
    if (state.tamper) {
      // Flip one byte of the value, then verify the *corrupted* read: the check
      // must reject it. Proves the gateway can't slip a forged value past you.
      const bad = provenReadFromJson({
        ...toJson(resp),
        value: flipFirstByteHex(toHex(resp.value)),
      });
      read = bad;
      tampered = true;
    }
    const ok = verifyProvenRead(read, rootBytes);
    const badge = ok
      ? `<span class="badge ok">✓ verified against the root</span>`
      : `<span class="badge bad">✗ ${tampered ? "tampered — rejected" : "FAILED verification"}</span>`;
    out.innerHTML = `<div class="result">
      <div class="headline">
        <span class="val">${renderValue(read.value)}</span>
        ${badge}
        ${tampered ? `<span class="cat">value corrupted client-side</span>` : ``}
      </div>
      <div class="kv">table   ${table}</div>
      <div class="kv">key     ${key}</div>
      <div class="kv">tree    ${read.treeVersion}</div>
      <div class="kv">root    ${state.root}</div>
      <p class="hint" style="margin:8px 0 0">${
        ok
          ? "The inclusion proof checks out: this value really is in committed state under the root above."
          : "The proof does not check out — so the explorer refuses to show it as real. This is the gateway being caught, not trusted."
      }</p>
    </div>`;
  } catch (e) {
    out.innerHTML = `<div class="result"><div class="badge bad">error</div><p class="hint">${escapeHtml(String(e.message || e))}</p></div>`;
  }
}

// Re-serialise a verified ProvenRead back to its JSON shape for tampering.
function toJson(read) {
  return {
    table: toHex(read.table),
    key: toHex(read.key),
    value: read.value === null ? undefined : toHex(read.value),
    tableRoot: toHex(read.tableRoot),
    treeVersion: read.treeVersion,
    rowProof: {
      siblings: read.rowProof.siblings.map(toHex),
      ...(read.rowProof.otherLeaf
        ? { otherLeaf: { key: toHex(read.rowProof.otherLeaf.key), value: toHex(read.rowProof.otherLeaf.value) } }
        : {}),
    },
    storeProof: { leafIndex: read.storeProof.leafIndex, siblings: read.storeProof.siblings.map(toHex) },
  };
}
function flipFirstByteHex(hex) {
  if (hex.length < 2) return "ff";
  const b = (parseInt(hex.slice(0, 2), 16) ^ 0xff).toString(16).padStart(2, "0");
  return b + hex.slice(2);
}

// ── ui wiring ────────────────────────────────────────────────────────────────

function wireUI() {
  $("searchBtn").addEventListener("click", runSearch);
  $("q").addEventListener("keydown", (e) => e.key === "Enter" && runSearch());
  $("tamperChip").addEventListener("click", (e) => {
    state.tamper = !state.tamper;
    e.target.classList.toggle("on", state.tamper);
    e.target.textContent = `tamper: ${state.tamper ? "on" : "off"}`;
    if ($("q").value.trim()) runSearch();
  });
  document.querySelectorAll("#filters .chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      state.filter = chip.getAttribute("data-cat");
      document.querySelectorAll("#filters .chip").forEach((c) => c.classList.toggle("on", c === chip));
      applyFilter();
    });
  });
}

// ── small helpers ────────────────────────────────────────────────────────────

function flash(el) {
  el.classList.remove("flash");
  void el.offsetWidth;
  el.classList.add("flash");
}
function timeAgo(d) {
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 2) return "just now";
  if (s < 60) return `${s}s ago`;
  return `${Math.floor(s / 60)}m ago`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

boot().catch((e) => {
  $("banner").innerHTML = `<b>Failed to start:</b> ${escapeHtml(String(e.message || e))}`;
  $("led").className = "led down";
  $("statusText").textContent = "error";
});

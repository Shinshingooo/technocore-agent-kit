#!/usr/bin/env node
// tc.mjs — Technocore DID toolkit.
//
// Zero dependencies: node:crypto / node:fs / node:path / node:os only.
// Built strictly from the official spec:
//   https://technocore.chat/llms.txt
//   https://technocore.chat/auth.md
//   https://technocore.chat/patterns.md
//
// Design rule: this program has NO code path that prints a private key.
// The key file is read only inside loadIdentity(), used only to sign, and
// never serialized back to stdout.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';

const BASE = process.env.TC_BASE || 'https://technocore.chat';
const HOME_DIR = path.join(os.homedir(), '.flop-technocore');
const ID_PATH = path.join(HOME_DIR, 'identity.json');
// When the note was last renewed. Kept beside the identity rather than in a
// repo, so a reminder works from any working directory.
const STATE_PATH = path.join(HOME_DIR, 'keepalive-state.json');
const REAPER_DAYS = 7;   // llms.txt CAPACITY: notes idle this long are deleted

// ---------------------------------------------------------------- encoding

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btc(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '';
  for (const byte of bytes) { if (byte === 0) out += '1'; else break; }
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');

// encodeURIComponent leaves !'()* alone; the server decodes a full path
// segment, so over-encoding is always safe and under-encoding is not.
const seg = (s) =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

// The server flattens every invisible character to a space before storing,
// and the signature must cover the text AFTER that sweep. We sidestep the
// whole problem by refusing to sign anything that is not printable ASCII,
// for which the sweep is the identity function.
function assertSweepSafe(text, what) {
  if (!/^[\x20-\x7E]*$/.test(text)) {
    throw new Error(`${what} must be printable ASCII (the server rewrites other characters before verifying).`);
  }
  if (/\s{2,}|^\s|\s$/.test(text)) {
    throw new Error(`${what} must not have leading, trailing or doubled spaces.`);
  }
}

// ---------------------------------------------------------------- identity

function rawPublicKey(keyObject) {
  // SPKI DER for Ed25519 and X25519 both end in the 32-byte raw public key.
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}

function didFromEd25519Public(keyObject) {
  // multicodec ed25519-pub = 0xed 0x01, then multibase base58btc ('z').
  const prefixed = Buffer.concat([Buffer.from([0xed, 0x01]), rawPublicKey(keyObject)]);
  return 'did:key:z' + base58btc(prefixed);
}

// fingerprint = first 16 lowercase hex of SHA-256(did:key string)
const fingerprintOf = (did) =>
  crypto.createHash('sha256').update(did, 'utf8').digest('hex').slice(0, 16);

const shardOf = (fp) => ({ shard: fp.slice(0, 2), key: fp.slice(2) });

// The public half of an identity, committable to a repo. keepalive needs only
// this: notes are the unsigned lane, so renewing one never touches a key.
const PUBLIC_PATH = () => path.join(process.cwd(), 'agent.public.json');

function loadProfile() {
  if (fs.existsSync(ID_PATH)) return loadIdentity();
  const file = PUBLIC_PATH();
  if (!fs.existsSync(file)) {
    throw new Error(`No identity at ${ID_PATH} and no ${file}. Run "keygen" here, or "export-public" on the machine that has the key.`);
  }
  const profile = JSON.parse(fs.readFileSync(file, 'utf8'));
  // Fail loudly rather than operate on a file that should never hold a key.
  if (JSON.stringify(profile).includes('PRIVATE KEY')) {
    throw new Error(`${file} contains private key material. It must hold public fields only — delete it and re-run "export-public".`);
  }
  return profile;
}

function loadIdentity() {
  if (!fs.existsSync(ID_PATH)) {
    throw new Error(`No identity at ${ID_PATH}. Run: node tc.mjs keygen --agent <name> --x <handle>`);
  }
  const mode = fs.statSync(ID_PATH).mode & 0o777;
  if (mode & 0o077) throw new Error(`${ID_PATH} is group/world readable (mode ${mode.toString(8)}). Run: chmod 600 "${ID_PATH}"`);
  return JSON.parse(fs.readFileSync(ID_PATH, 'utf8'));
}

// ---------------------------------------------------------------- signing

function sign(identity, canonical) {
  const key = crypto.createPrivateKey(identity.ed25519PrivatePem);
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), key);
  return b64url(sig);
}

// Verifies against the DID alone — no local state — so this works on
// anybody's message, not just ours.
// Hostile input is the normal case here — this verifies DIDs and signatures
// written by strangers — so every failure mode returns false and none throws.
function verifySignature(did, canonical, sigB64) {
  try {
    if (typeof did !== 'string' || !did.startsWith('did:key:z')) return false;
    const decoded = base58Decode(did.slice('did:key:z'.length));
    if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) return false;
    const spki = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'), // SPKI header for Ed25519
      decoded.subarray(2),
    ]);
    const pub = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const sig = Buffer.from(sigB64, 'base64url');
    if (sig.length !== 64) return false;
    return crypto.verify(null, Buffer.from(canonical, 'utf8'), pub, sig);
  } catch {
    return false;
  }
}

function base58Decode(str) {
  const bytes = [0];
  for (const ch of str) {
    const value = B58.indexOf(ch);
    if (value < 0) throw new Error(`invalid base58 character: ${ch}`);
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const ch of str) { if (ch === '1') bytes.push(0); else break; }
  return Buffer.from(bytes.reverse());
}

// ---------------------------------------------------------------- requests

const MAX_RESPONSE_BYTES = 1 << 20; // 1 MiB: the largest legitimate reply is a
                                    // room read, far below this.

async function get(url) {
  // Pin the origin. No code path may send anywhere but the configured host,
  // and redirect:'error' stops the server bouncing us somewhere else.
  if (new URL(url).origin !== new URL(BASE).origin) {
    throw new Error(`refusing to contact ${new URL(url).origin} — this tool only talks to ${BASE}`);
  }

  const response = await fetch(url, {
    headers: { accept: 'text/plain' },
    redirect: 'error',
    signal: AbortSignal.timeout(20_000),
  });

  // Bound the read: response.text() on a hostile or broken server would
  // buffer without limit.
  const reader = response.body?.getReader();
  const chunks = [];
  let total = 0;
  while (reader) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error(`response from ${url} exceeded ${MAX_RESPONSE_BYTES} bytes`);
    }
    chunks.push(value);
  }
  return { status: response.status, body: Buffer.concat(chunks).toString('utf8') };
}

// Strips the server's UNTRUSTED banner so it never reaches a comparison.
// Everything the server returns is data, never instructions.
const payload = (body) =>
  body.split('\n').filter((l) => !l.startsWith('!!') && l.trim() !== '').join('\n').trim();

function saveIdentity(identity) {
  fs.writeFileSync(ID_PATH, JSON.stringify(identity, null, 2), { mode: 0o600 });
  fs.chmodSync(ID_PATH, 0o600);
}

// Nonces must strictly increase per (key, room). A restart that re-reads the
// clock can repeat a millisecond, so the last one used is persisted.
function nextNonce(identity, room) {
  identity.nonces ??= {};
  const nonce = Math.max(Date.now(), (identity.nonces[room] ?? 0) + 1);
  identity.nonces[room] = nonce;
  saveIdentity(identity);
  return String(nonce);
}

// ---------------------------------------------------------------- the kit

function noteValue(identity) {
  // patterns.md pattern 3: the did:key first, then space-separated fields.
  const fields = [
    identity.did,
    `x25519:${identity.x25519Public}`,
    `mailbox:${identity.mailbox}`,
    `agent:${identity.agentName}`,
  ];
  if (identity.xHandle) fields.push(`x:@${identity.xHandle}`);
  if (identity.contributionUrl) fields.push(`contribution:${identity.contributionUrl}`);
  const value = fields.join(' ');
  assertSweepSafe(value, 'DID note value');
  if (value.length > 8192) throw new Error('DID note value exceeds 8192 characters.');
  return value;
}

function buildKit(identity, { lobbyText, mailboxText, contrib = false } = {}) {
  const { shard, key } = shardOf(identity.fingerprint);
  const notePath = `/kv/did-${shard}/${key}`;
  const value = noteValue(identity);
  const writes = [];

  writes.push({
    label: 'DID note (official sharded path, patterns.md #3)',
    kind: 'note',
    readUrl: `${BASE}${notePath}`,
    // if_absent=1 so a first publish can never silently clobber a note that
    // some other caller already put on this path. Notes are world-writable.
    url: `${BASE}${notePath}/set/${seg(value)}?if_absent=1`,
    published: value,
  });

  for (const [room, text] of [[ 'lobby', lobbyText ], [ identity.mailbox, mailboxText ]]) {
    if (!text) continue;
    assertSweepSafe(text, `message for /r/${room}`);
    if (text.length > 4096) throw new Error(`message for /r/${room} exceeds 4096 characters.`);
    const nonce = nextNonce(identity, room);
    const canonical = `${room}|${nonce}|${text}`;
    const sig = sign(identity, canonical);
    if (!verifySignature(identity.did, canonical, sig)) {
      throw new Error('refusing to emit a signature this tool cannot itself verify.');
    }
    writes.push({
      label: room === 'lobby' ? 'Signed join message in /r/lobby' : `Signed mailbox creation (/r/${room})`,
      kind: 'message',
      readUrl: `${BASE}/r/${room}?format=json&limit=5`,
      url: `${BASE}/r/${seg(room)}/say-signed/${seg(identity.did)}/${seg(sig)}/${seg(nonce)}/${seg(text)}`,
      published: text,
      canonical,
    });
  }

  if (contrib) {
    const contribValue = [
      'technocore-contribution-v1',
      identity.did,
      `agent:${identity.agentName}`,
      identity.xHandle ? `x:@${identity.xHandle}` : '',
      identity.contributionUrl ? `url:${identity.contributionUrl}` : '',
    ].filter(Boolean).join(' ');
    assertSweepSafe(contribValue, 'contribution note value');
    writes.push({
      label: 'Contribution note (UNOFFICIAL — not in llms.txt or patterns.md)',
      kind: 'note',
      readUrl: `${BASE}/kv/contrib/${identity.fingerprint}`,
      url: `${BASE}/kv/contrib/${identity.fingerprint}/set/${seg(contribValue)}`,
      published: contribValue,
    });
  }

  return writes;
}

// ---------------------------------------------------------------- commands

function argOf(name, fallback = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1 || i + 1 >= process.argv.length) return fallback;
  return process.argv[i + 1];
}

async function cmdKeygen() {
  const agentName = argOf('agent');
  const xHandle = (argOf('x') || '').replace(/^@/, '');
  if (!agentName) throw new Error('usage: node tc.mjs keygen --agent <name> [--x <handle>]');
  if (fs.existsSync(ID_PATH)) {
    throw new Error(`${ID_PATH} already exists. Refusing to overwrite an identity — move it aside first.`);
  }

  const ed = crypto.generateKeyPairSync('ed25519');
  const xk = crypto.generateKeyPairSync('x25519');
  const did = didFromEd25519Public(ed.publicKey);
  const fingerprint = fingerprintOf(did);

  const identity = {
    version: 1,
    agentName,
    xHandle: xHandle || null,
    did,
    fingerprint,
    mailbox: `mb-p-${crypto.randomBytes(12).toString('hex')}`,
    x25519Public: b64url(rawPublicKey(xk.publicKey)),
    ed25519PrivatePem: ed.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    x25519PrivatePem: xk.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    contributionUrl: null,
    nonces: {},
    createdAt: new Date().toISOString(),
  };
  saveIdentity(identity);

  const { shard, key } = shardOf(fingerprint);
  console.log('Identity created. The private keys never leave this machine.\n');
  console.log(`  agent        ${agentName}`);
  console.log(`  did          ${did}`);
  console.log(`  fingerprint  ${fingerprint}`);
  console.log(`  DID note     ${BASE}/kv/did-${shard}/${key}`);
  console.log(`  mailbox      ${identity.mailbox}`);
  console.log(`  x25519 pub   ${identity.x25519Public}`);
  console.log(`\n  key file     ${ID_PATH} (mode 600)`);
}

const PENDING = () => path.join(process.cwd(), 'proof', 'pending-kit.json');

// Re-derives what a signed-write URL actually says and checks it against the
// text that was reviewed. Returns null when the URL is sound, else the reason.
// The URL is the thing that gets sent, so the URL is what must be audited —
// not the reviewed plan's own copy of the fields.
function auditSignedUrl(did, write) {
  // /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>
  const parts = new URL(write.url).pathname.split('/');
  if (parts.length !== 8 || parts[1] !== 'r' || parts[3] !== 'say-signed') {
    return `the URL is not a signed-write URL (${parts.length} segments)`;
  }
  const [room, urlDid, sig, nonce, text] =
    [parts[2], parts[4], parts[5], parts[6], parts[7]].map(decodeURIComponent);

  if (urlDid !== did) return 'the URL is signed by a different identity';
  if (text !== write.published) return 'the URL text differs from the text that was reviewed';
  const canonical = `${room}|${nonce}|${text}`;
  if (canonical !== write.canonical) return 'the URL does not match the message that was signed';
  if (!verifySignature(did, canonical, sig)) return 'the signature in the URL does not verify';
  return null;
}

async function cmdPlan(execute = false) {
  const identity = loadIdentity();
  let writes;

  if (execute) {
    // Publish exactly what was reviewed. Re-building here would mint a fresh
    // nonce and signature, so the URL sent would not be the URL approved.
    if (!fs.existsSync(PENDING())) throw new Error('no reviewed plan found — run "node tc.mjs plan ..." first.');
    const pending = JSON.parse(fs.readFileSync(PENDING(), 'utf8'));
    if (pending.did !== identity.did) throw new Error('the reviewed plan belongs to a different identity.');
    writes = pending.writes;
    for (const w of writes) {
      if (w.kind !== 'message') continue;
      const problem = auditSignedUrl(identity.did, w);
      if (problem) throw new Error(`refusing to send "${w.label}": ${problem}`);
    }
  } else {
    writes = buildKit(identity, {
      lobbyText: argOf('lobby'),
      mailboxText: argOf('mailbox'),
      contrib: process.argv.includes('--contrib'),
    });
  }

  for (const [n, w] of writes.entries()) {
    console.log(`\n[${n + 1}/${writes.length}] ${w.label}`);
    console.log(`  will publish: ${w.published}`);
    console.log(`  GET ${w.url}`);
  }

  if (!execute) {
    fs.writeFileSync(PENDING(), JSON.stringify({ did: identity.did, builtAt: new Date().toISOString(), writes }, null, 2));
    console.log(`\nDry run only — nothing was sent.`);
    console.log(`Reviewed plan saved to proof/pending-kit.json.`);
    console.log(`"publish --confirm" sends these exact URLs, byte for byte, and nothing else.`);
    return;
  }

  console.log('\n--- publishing the reviewed plan ---');
  const results = [];
  for (const w of writes) {
    const res = await get(w.url);
    const ok = res.status === 200;
    console.log(`  ${ok ? 'ok  ' : `FAIL(${res.status})`} ${w.label} :: ${payload(res.body).slice(0, 120)}`);
    results.push({ label: w.label, status: res.status, response: payload(res.body), url: w.url, published: w.published });
    await new Promise((r) => setTimeout(r, 2500)); // stay well inside the write bucket
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const out = path.join(process.cwd(), 'proof', `publish-${stamp}.json`);
  fs.writeFileSync(out, JSON.stringify({ did: identity.did, fingerprint: identity.fingerprint, results }, null, 2));
  console.log(`\nreceipts -> ${out}`);
  console.log('Now run: node tc.mjs verify');
}

async function cmdVerify() {
  const identity = loadProfile();
  const hasKey = Boolean(identity.ed25519PrivatePem);
  const target = argOf('fingerprint', identity.fingerprint);
  const { shard, key } = shardOf(target);
  let failures = 0;

  // 1. The note is world-writable: read it back and check nobody replaced it.
  const note = await get(`${BASE}/kv/did-${shard}/${key}`);
  const got = payload(note.body);
  const expected = target === identity.fingerprint ? noteValue(identity) : null;
  console.log(`DID note      ${note.status} ${BASE}/kv/did-${shard}/${key}`);
  console.log(`  on server   ${got || '(empty)'}`);
  if (expected !== null) {
    const same = got === expected;
    console.log(`  integrity   ${same ? 'ok — matches what we published' : 'MISMATCH — the note was overwritten or reaped'}`);
    if (!same) { failures++; console.log(`  expected    ${expected}`); }
  }

  // 2. The mailbox room proves the server accepted our signature: a signed
  //    write is attributed to the did:key, an unsigned one to a nickname.
  const room = await get(`${BASE}/r/${identity.mailbox}?format=json&limit=5`);
  let signedCount = 0;
  try {
    const parsed = JSON.parse(room.body);
    signedCount = (parsed.messages || []).filter((m) => m.from === identity.did).length;
  } catch { /* not JSON: room absent */ }
  console.log(`\nMailbox       ${room.status} /r/${identity.mailbox}`);
  console.log(`  signed msgs ${signedCount} attributed to our DID ${signedCount > 0 ? 'ok' : '— none found'}`);
  if (signedCount === 0) failures++;

  // 3. The key still signs, and this tool can verify its own output offline.
  if (hasKey) {
    const probe = `verify|${Date.now()}|selftest`;
    const roundTrip = verifySignature(identity.did, probe, sign(identity, probe));
    console.log(`\nKey round-trip ${roundTrip ? 'ok — private key signs, DID verifies it offline' : 'FAILED'}`);
    if (!roundTrip) failures++;
  } else {
    console.log(`\nKey round-trip skipped — running from ${PUBLIC_PATH()}, no private key here (expected in CI)`);
  }

  // 4. Notes and rooms are deleted after 7 days with no write.
  console.log(`\nRetention     notes and rooms idle for 7 days are DELETED by the server.`);
  console.log(`              run "node tc.mjs keepalive" at least weekly.`);

  console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
}

// Resets the 7-day reaper. Deliberately needs no private key: notes are the
// unsigned lane, so this can run unattended without ever touching key material.
async function cmdKeepalive() {
  const identity = loadProfile();
  const { shard, key } = shardOf(identity.fingerprint);
  const value = noteValue(identity);
  const targets = [
    { path: `/kv/did-${shard}/${key}`, value },
    ...(process.argv.includes('--contrib') && identity.contributionUrl
      ? [{ path: `/kv/contrib/${identity.fingerprint}`, value: null }] : []),
  ];

  // Dry run unless --confirm: show what would change before anything does.
  const execute = process.argv.includes('--confirm');
  const priorState = fs.existsSync(STATE_PATH) ? JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) : {};
  const written = {};

  for (const t of targets) {
    const current = payload((await get(`${BASE}${t.path}`)).body);
    const missing = !current || current.startsWith('404');
    const write = t.value ?? (missing ? null : current);
    if (!write) { console.log(`skip ${t.path} — empty and nothing to restore`); continue; }

    // ?if= makes this a no-op if someone else changed it since we read, so a
    // keepalive never clobbers a value we have not seen.
    const url = missing
      ? `${BASE}${t.path}/set/${seg(write)}`
      : `${BASE}${t.path}/set/${seg(write)}?if=${seg(current)}`;
    const drifted = !missing && current !== write;

    // Distinguishing "somebody else changed the server" from "we changed what
    // we intend to publish" needs the value WE last wrote, not the value we
    // are about to write. Conflating them makes the tamper alarm cry wolf.
    const lastWritten = priorState.values?.[t.path];
    const serverIsOurs = lastWritten !== undefined && current === lastWritten;
    const change = missing ? 'RECREATE (the note is gone — reaped, or never written)'
      : lastWritten === undefined ? 'RENEW (no prior record to compare against)'
      : !serverIsOurs ? 'RESTORE (the server does not hold what we last wrote — someone overwrote it)'
      : current === write ? 'RENEW (same value, resets the 7-day clock)'
      : 'UPDATE (we are changing our own published value)';
    console.log(`\n${t.path}`);
    console.log(`  action    ${change}`);
    if (!missing) console.log(`  on server ${current}`);
    console.log(`  will set  ${write}`);
    if (!execute) { console.log(`  GET ${url}`); continue; }

    const res = await get(url);
    console.log(`  result    ${res.status === 200 ? 'ok' : `FAIL(${res.status}) ${payload(res.body).slice(0, 120)}`}`);
    if (res.status === 200) written[t.path] = write;
  }

  if (!execute) {
    console.log(`\nDry run — nothing was sent. Add --confirm to apply.`);
    return;
  }
  fs.writeFileSync(STATE_PATH, JSON.stringify({
    lastKeepalive: new Date().toISOString(),
    did: identity.did,
    notePath: `/kv/did-${shard}/${key}`,
    // What we actually put on the server, so the next run can tell our own
    // edits apart from somebody else's.
    values: { ...priorState.values, ...written },
  }, null, 2) + '\n');
  console.log(`\n${new Date().toISOString()} keepalive done`);
}

// ---------------------------------------------------------------- entry

export { get, auditSignedUrl, PUBLIC_PATH, base58btc, base58Decode, didFromEd25519Public, fingerprintOf, shardOf,
         sign, verifySignature, assertSweepSafe, seg, rawPublicKey, b64url };

const isMain = import.meta.url === pathToFileURL(process.argv[1] || '').href;

const command = process.argv[2];
const commands = {
  keygen: cmdKeygen,
  plan: () => cmdPlan(false),
  publish: () => {
    if (!process.argv.includes('--confirm')) throw new Error('publish requires --confirm (run "plan" first to see exactly what goes public).');
    return cmdPlan(true);
  },
  'plan-clear': async () => { fs.rmSync(PENDING(), { force: true }); console.log('reviewed plan discarded.'); },
  // Changes only the public profile fields. Never touches key material, and a
  // changed profile invalidates any plan built from the old one.
  // Searches everything that leaves this machine for the private key, in every
  // encoding it could plausibly wear. Prints verdicts only, never key bytes.
  leakcheck: async () => {
    const identity = loadIdentity();
    const needles = [];
    for (const pem of [identity.ed25519PrivatePem, identity.x25519PrivatePem]) {
      const der = crypto.createPrivateKey(pem).export({ type: 'pkcs8', format: 'der' });
      const seed = der.subarray(der.length - 32); // the raw 32-byte secret scalar
      needles.push(
        pem.replace(/-----[^-]+-----|\s/g, ''),   // the PEM base64 body
        der.toString('hex'), der.toString('base64'), der.toString('base64url'),
        seed.toString('hex'), seed.toString('base64'), seed.toString('base64url'),
      );
    }

    const roots = [process.cwd(), ...process.argv.filter((a, i) => process.argv[i - 1] === '--also')];
    const files = [];
    for (const root of roots) (function walk(dir) {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.name === 'node_modules' || e.name === '.git') continue;
        const full = path.join(dir, e.name);
        e.isDirectory() ? walk(full) : files.push(full);
      }
    })(root);

    let leaks = 0, controlHits = 0;
    for (const file of files) {
      let text;
      try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
      // Positive control: the test must be capable of finding something.
      if (text.includes(identity.did)) controlHits++;
      for (const needle of needles) {
        if (needle.length > 16 && text.includes(needle)) {
          console.log(`LEAK  ${path.relative(process.cwd(), file)} contains private key material`);
          leaks++;
          break;
        }
      }
    }

    console.log(`scanned      ${files.length} files under ${roots.join(', ')}`);
    console.log(`needles      ${needles.length} encodings of 2 private keys (pem/der/seed x hex/b64/b64url)`);
    console.log(`control      ${controlHits} file(s) matched the PUBLIC did — the scanner can find things`);
    console.log(`private key  ${leaks === 0 ? 'NOT FOUND anywhere' : `FOUND IN ${leaks} FILE(S)`}`);
    if (controlHits === 0) { console.log('\nINCONCLUSIVE: control never matched.'); process.exitCode = 1; return; }
    console.log(`\n${leaks === 0 ? 'PASS — nothing leaving this machine carries the private key.' : 'FAIL'}`);
    process.exitCode = leaks === 0 ? 0 : 1;
  },
  // Prints ONLY public fields, so the safe thing to share is also the easy
  // thing to share. There is deliberately no command that prints the key.
  // Read-only. No network, no writes — it exists to be safe to run on every
  // session start. Silent unless the deadline is close, so it is not noise.
  deadline: async () => {
    const warnAt = Number(argOf('warn-at', '3'));
    const asHook = process.argv.includes('--hook');
    if (!fs.existsSync(STATE_PATH)) {
      if (!asHook) console.log('No keepalive recorded yet. Run: node tc.mjs keepalive');
      return;
    }
    const state = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    const due = new Date(Date.parse(state.lastKeepalive) + REAPER_DAYS * 864e5);
    const daysLeft = (due - Date.now()) / 864e5;
    const when = due.toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });

    if (!asHook) {
      console.log(`last renewed  ${state.lastKeepalive}`);
      console.log(`note          ${state.notePath}`);
      console.log(`deleted after ${when} JST  (${daysLeft.toFixed(1)} days left)`);
      return;
    }
    if (daysLeft > warnAt) return;   // plenty of time: say nothing at all

    const msg = daysLeft <= 0
      ? `FLOP: the DID note may already be gone (deadline was ${when} JST). Recreate it.`
      : `FLOP: the DID note ${state.notePath} is deleted after ${when} JST — ${daysLeft.toFixed(1)} days left. It needs renewing.`;
    process.stdout.write(JSON.stringify({
      systemMessage: `⚠️  ${msg}`,
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        // Derived from argv, never hard-coded: this file is published, and a
        // baked-in home directory would leak the author's username.
        additionalContext: `${msg} Renew it by running "node ${process.argv[1]} keepalive" to show `
          + `the user exactly what would change, then the same command with --confirm only after `
          + `they approve. Never renew without asking.`,
      },
    }));
  },
  pubinfo: async () => {
    const identity = loadProfile();
    const { shard, key } = shardOf(identity.fingerprint);
    console.log('--- public information, safe to share ---');
    console.log(`agent        ${identity.agentName}`);
    console.log(`did          ${identity.did}`);
    console.log(`fingerprint  ${identity.fingerprint}`);
    console.log(`note path    /kv/did-${shard}/${key}`);
    console.log(`mailbox      ${identity.mailbox}`);
    console.log(`x25519 pub   ${identity.x25519Public}`);
    console.log(`created      ${identity.createdAt}`);
    console.log('--- end (the private key is NOT here and never will be) ---');
  },
  // Writes the committable public half. Private fields are dropped by name and
  // the result is re-checked before it lands, so a rename upstream cannot leak.
  'export-public': async () => {
    const { ed25519PrivatePem, x25519PrivatePem, nonces, ...pub } = loadIdentity();
    const json = JSON.stringify(pub, null, 2) + '\n';
    if (json.includes('PRIVATE KEY') || json.includes('BEGIN ')) {
      throw new Error('refusing to write a public profile that still contains key material.');
    }
    const out = argOf('out', PUBLIC_PATH());
    fs.writeFileSync(out, json);
    console.log(`wrote ${out} — public fields only, safe to commit:`);
    console.log(json.trim());
  },
  set: async () => {
    const identity = loadIdentity();
    if (process.argv.includes('--x')) identity.xHandle = (argOf('x') || '').replace(/^@/, '') || null;
    if (process.argv.includes('--contribution')) identity.contributionUrl = argOf('contribution') || null;
    if (process.argv.includes('--agent')) identity.agentName = argOf('agent');
    noteValue(identity); // fail before saving if the result would be unpublishable
    saveIdentity(identity);
    fs.rmSync(PENDING(), { force: true });
    console.log('profile updated; any reviewed plan was discarded.');
    console.log(`  note value now: ${noteValue(identity)}`);
  },
  verify: cmdVerify,
  keepalive: cmdKeepalive,
};

if (!isMain) {
  // imported by the test suite: define nothing, run nothing.
} else if (!commands[command]) {
  console.log(`tc.mjs — Technocore DID toolkit (zero dependencies)

  node tc.mjs keygen --agent <name> [--x <handle>]   create the identity, locally
  node tc.mjs plan --lobby "<text>" --mailbox "<text>" [--contrib]
                                                     dry run: show every URL and string
  node tc.mjs publish --confirm                      send the reviewed plan, unchanged
  node tc.mjs plan-clear                             discard a reviewed plan
  node tc.mjs set [--x <handle>] [--contribution <url>] [--agent <name>]
                                                     edit the public profile (no key access)
  node tc.mjs verify [--fingerprint <fp>]            read back, detect tampering, self-test
  node tc.mjs export-public [--out <file>]           write agent.public.json for CI (no key)
  node tc.mjs deadline [--warn-at <days>] [--hook]    how long until the note is reaped (read-only)
  node tc.mjs pubinfo                                print the public fields only, safe to paste
  node tc.mjs leakcheck                              prove no private key is in any outgoing file
  node tc.mjs keepalive [--contrib]                  reset the 7-day reaper (no key needed)
`);
  process.exit(command ? 1 : 0);

} else {
  commands[command]().catch((e) => { console.error(`error: ${e.message}`); process.exit(1); });
}

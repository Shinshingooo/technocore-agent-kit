#!/usr/bin/env node
// Measures how many identities registered in /kv/contrib still have a DID note
// you can actually reach.
//
//   node survey.mjs [--sample 150]
//
// Method, so the number can be argued with:
//   1. list /kv/contrib
//   2. take an even slice across the listing, not the first N — the listing is
//      sorted, so the head of it is skewed toward whoever registered first
//   3. read each entry and pull the did:key OUT OF THE VALUE, rather than
//      trusting that the note's key equals the fingerprint (it does not always)
//   4. compute the fingerprint from that did ourselves
//   5. look for a note at the sharded path, then at the legacy flat path
//
// What a "gone" result does and does not mean: it means nothing is published
// at the path derived from the DID that entry itself declares. It does NOT
// prove the note was reaped — the identity may never have published one. The
// 7-day reaper is the likeliest explanation for most of them, not a proven one.

import crypto from 'node:crypto';

const BASE = process.env.TC_BASE || 'https://technocore.chat';
const sampleSize = Number(process.argv[process.argv.indexOf('--sample') + 1]) || 150;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Everything this service returns is anonymous input. Strip its own banner and
// treat the rest as data.
const strip = (body) =>
  body.split('\n').filter((l) => !l.startsWith('!!') && l.trim()).join('\n').trim();

async function get(path) {
  const res = await fetch(`${BASE}${path}`, { headers: { accept: 'text/plain' } });
  const body = strip(await res.text());
  await sleep(200);   // limits are published at /.well-known/agent.json
  return body;
}

// A missing note answers 200 with a "404 no note …" body, not an HTTP 404.
const exists = (body) => Boolean(body) && !body.includes('no note') && !body.startsWith('404');
const fingerprintOf = (did) =>
  crypto.createHash('sha256').update(did, 'utf8').digest('hex').slice(0, 16);

const listing = await (await fetch(`${BASE}/kv/contrib`)).text();
const keys = [...listing.matchAll(/\/kv\/contrib\/([0-9a-f]{16})/g)].map((m) => m[1]);
const step = Math.max(1, Math.floor(keys.length / sampleSize));
const sample = keys.filter((_, i) => i % step === 0).slice(0, sampleSize);

const tally = { noDid: 0, keyMismatch: 0, sharded: 0, legacy: 0, gone: 0 };

for (const key of sample) {
  const value = await get(`/kv/contrib/${key}`);
  // Tolerant on purpose: several popular tools emit "did:did:key:z6Mk…".
  const found = value.match(/did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}/);
  if (!found) { tally.noDid++; continue; }

  const did = found[0];
  const fp = fingerprintOf(did);
  if (fp !== key) tally.keyMismatch++;

  if (exists(await get(`/kv/did-${fp.slice(0, 2)}/${fp.slice(2)}`))) { tally.sharded++; continue; }
  if (exists(await get(`/kv/did/${fp}`)))                            { tally.legacy++;  continue; }
  tally.gone++;
}

const n = sample.length;
const pct = (x) => `${Math.round((x / n) * 100)}%`.padStart(4);
const live = tally.sharded + tally.legacy;

console.log(`
${new Date().toISOString()}   ${BASE}

  contrib entries        ${keys.length}
  sampled                ${n}

  no did:key in the entry     ${tally.noDid}
  note key != fingerprint     ${tally.keyMismatch}

  --- resolved from the DID each entry declares ---
  live, sharded path          ${tally.sharded}  ${pct(tally.sharded)}
  live, legacy flat path      ${tally.legacy}  ${pct(tally.legacy)}
  no DID note reachable       ${tally.gone}  ${pct(tally.gone)}

  of the ${live} still reachable, ${tally.legacy} (${Math.round((tally.legacy / live) * 100)}%) are on the legacy path
`);

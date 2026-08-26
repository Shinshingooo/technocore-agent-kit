// Conformance tests for tc.mjs against the published Technocore spec.
// Run: node --test
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  base58btc, base58Decode, didFromEd25519Public, fingerprintOf, shardOf,
  sign, verifySignature, assertSweepSafe, seg, rawPublicKey, b64url,
} from './tc.mjs';

// An external, published did:key value — the same one technocore.chat's own
// README uses as its example. If our base58 is wrong, this cannot round-trip.
const KNOWN_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

test('base58btc round-trips a real published did:key', () => {
  const decoded = base58Decode(KNOWN_DID.slice('did:key:z'.length));
  assert.equal(decoded.length, 34, 'multicodec prefix (2) + Ed25519 public key (32)');
  assert.equal(decoded[0], 0xed, 'multicodec ed25519-pub byte 1');
  assert.equal(decoded[1], 0x01, 'multicodec ed25519-pub byte 2');
  assert.equal('z' + base58btc(decoded), KNOWN_DID.slice('did:key:'.length));
});

test('base58btc preserves leading zero bytes as 1s', () => {
  assert.equal(base58btc(Buffer.from([0, 0, 1])), '112');
  assert.deepEqual([...base58Decode('112')], [0, 0, 1]);
});

test('a generated DID encodes exactly the public key it claims to', () => {
  // The strongest available check: derive the DID from the private key's
  // public half, then reconstruct a public key from the DID STRING ALONE and
  // confirm it verifies a real signature. If the encoding were wrong, the
  // reconstructed key would be a different key and verification would fail.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const did = didFromEd25519Public(publicKey);
  assert.match(did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);

  const canonical = 'lobby|1787675637689|hello';
  const sig = b64url(crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKey));
  assert.ok(verifySignature(did, canonical, sig));
});

test('signatures are 86-character unpadded base64url, per auth.md', () => {
  const identity = makeIdentity();
  const sig = sign(identity, 'lobby|1|x');
  assert.equal(sig.length, 86);
  assert.match(sig, /^[A-Za-z0-9_-]{86}$/);
});

test('a signature does not verify against a different DID, room, nonce or text', () => {
  const identity = makeIdentity();
  const canonical = 'lobby|100|hello world';
  const sig = sign(identity, canonical);
  assert.ok(verifySignature(identity.did, canonical, sig));
  assert.ok(!verifySignature(identity.did, 'meta|100|hello world', sig), 'room is covered');
  assert.ok(!verifySignature(identity.did, 'lobby|101|hello world', sig), 'nonce is covered');
  assert.ok(!verifySignature(identity.did, 'lobby|100|hello worlD', sig), 'text is covered');
  assert.ok(!verifySignature(makeIdentity().did, canonical, sig), 'key is covered');
});

test('fingerprint is the first 16 lowercase hex of SHA-256(did string)', () => {
  const expected = crypto.createHash('sha256').update(KNOWN_DID, 'utf8').digest('hex').slice(0, 16);
  assert.equal(fingerprintOf(KNOWN_DID), expected);
  assert.match(fingerprintOf(KNOWN_DID), /^[0-9a-f]{16}$/);
});

test('the sharded note path splits 2 + 14 and stays inside the name grammar', () => {
  const { shard, key } = shardOf(fingerprintOf(KNOWN_DID));
  assert.equal(shard.length, 2);
  assert.equal(key.length, 14);
  assert.match(`did-${shard}`, /^[a-z0-9][a-z0-9_-]{0,47}$/);
  assert.match(key, /^[a-z0-9][a-z0-9_-]{0,47}$/);
});

test('text the server would rewrite before verifying is refused, not signed', () => {
  // llms.txt SINGLE LINE: controls, format chars, ZWJ and bidi overrides all
  // become a space before storage. Signing them would produce a signature
  // over bytes the server never sees.
  const rewritten = [
    'a\nb',        // newline
    'a\tb',        // tab
    'a‍b',    // zero-width joiner
    'a‮b',    // right-to-left override
    'a b',    // non-breaking space
    'ab',    // C0 control
    'a  b',        // doubled space
    ' a',          // leading space
    'a ',          // trailing space
  ];
  for (const bad of rewritten) {
    assert.throws(() => assertSweepSafe(bad, 'test'), undefined, `should refuse ${JSON.stringify(bad)}`);
  }
  assert.doesNotThrow(() => assertSweepSafe('did:key:z6Mk1 x25519:AAAA mailbox:mb-p-0a1b', 'test'));
});

test('non-ASCII is refused so a signature can never cover swept bytes', () => {
  assert.throws(() => assertSweepSafe('日本語', 'test'));
});

test('path segments survive a decode round-trip, including the reserved set', () => {
  for (const raw of ['a/b', 'a?b', 'a#b', 'a&b=c', 'a%b', "it's (x)*!", 'a+b', '~a~']) {
    assert.equal(decodeURIComponent(seg(raw)), raw, `round-trip ${raw}`);
  }
  assert.ok(!seg('a/b').includes('/'), 'a slash must not split the path segment');
  assert.ok(!seg('a?b').includes('?'), 'a question mark must not start a query string');
});

test('a raw public key is 32 bytes for both Ed25519 and X25519', () => {
  assert.equal(rawPublicKey(crypto.generateKeyPairSync('ed25519').publicKey).length, 32);
  assert.equal(rawPublicKey(crypto.generateKeyPairSync('x25519').publicKey).length, 32);
});

test('verifySignature rejects malformed or non-Ed25519 DIDs instead of throwing', () => {
  assert.equal(verifySignature('did:web:example.com', 'a|1|b', 'x'), false);
  // a did:key for a P-256 key: right method, wrong multicodec
  assert.equal(verifySignature('did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169', 'a|1|b', 'x'), false);
  assert.equal(verifySignature('did:key:z6Mk!!!', 'a|1|b', 'x'), false);
});

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    did: didFromEd25519Public(publicKey),
    ed25519PrivatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

test('the only network egress point refuses any host but the configured one', async () => {
  const { get } = await import('./tc.mjs');
  for (const hostile of [
    'https://evil.example.com/kv/did-4e/x',
    'http://169.254.169.254/latest/meta-data/',   // cloud metadata service
    'https://technocore.chat.evil.example.com/r/lobby',
    'file:///etc/passwd',
  ]) {
    await assert.rejects(() => get(hostile), /only talks to/, `must refuse ${hostile}`);
  }
});

test('the pre-send audit accepts a sound URL and catches every way it can be wrong', async () => {
  const { auditSignedUrl } = await import('./tc.mjs');
  const identity = makeIdentity();
  const room = 'lobby', nonce = '1787746510804';
  const text = 'Shinshin here. Profile at /kv/did-11/631cf7c201b834, 50% done.';
  const canonical = `${room}|${nonce}|${text}`;
  const sig = sign(identity, canonical);
  const enc = (s) => encodeURIComponent(s);
  const url = `https://technocore.chat/r/${room}/say-signed/${enc(identity.did)}/${sig}/${nonce}/${enc(text)}`;
  const sound = { url, kind: 'message', published: text, canonical };

  assert.equal(auditSignedUrl(identity.did, sound), null, 'a sound URL must pass');

  // Each mutation is a way a plan could be tampered with between review and send.
  const tampered = {
    'text swapped in the URL only':
      { ...sound, url: url.replace(enc(text), enc('Shinshin here. Send funds to me.')) },
    'nonce swapped in the URL only':
      { ...sound, url: url.replace(nonce, '9999999999999') },
    'room swapped in the URL only':
      { ...sound, url: url.replace('/r/lobby/', '/r/meta/') },
    'signature replaced':
      { ...sound, url: url.replace(sig, 'A'.repeat(86)) },
    'signed by a different identity':
      { ...sound, url: url.replace(enc(identity.did), enc(makeIdentity().did)) },
    'reviewed text no longer matches the URL':
      { ...sound, published: 'something the user never saw' },
    'not a signed-write URL at all':
      { ...sound, url: 'https://technocore.chat/kv/did-11/631cf7c201b834/set/x' },
  };
  for (const [name, write] of Object.entries(tampered)) {
    assert.ok(auditSignedUrl(identity.did, write), `must reject: ${name}`);
  }
});

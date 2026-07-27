// crates/s3tap-core/src/hash.rs
//
// A small, self-contained SHA-256 (FIPS 180-4) — vendored because the agent builds
// offline with no external crates, and the schema requires `key_hash`/`upload_id`
// to be `sha256:<hex>` so the object key is never stored in clear. Used only for
// hashing short identifiers (keys, upload ids), not a hot path.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 digest of `msg` as 32 raw bytes.
#[must_use]
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Padding: 0x80, then zeros, then the 64-bit big-endian bit length.
    let mut data = msg.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for block in data.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (hi, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *hi = hi.wrapping_add(v);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA256 (RFC 2104) over the vendored [`sha256`].
///
/// Vendored for the same reason the hash is: the agent builds with no external crates, and
/// the construction is fifteen lines. Used to key the object-key hash with the per-run salt.
/// The naive alternative — `SHA256(salt || key)` — is a SECRET-PREFIX MAC, and Merkle-Damgård
/// makes that forgeable by length extension: from one observed `(key, hash)` pair anyone can
/// compute the digest of `key || padding || suffix` WITHOUT the salt, i.e. produce valid
/// salted hashes for keys they never saw and confirm a guessed prefix. HMAC's two-pass
/// construction closes that.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64; // SHA-256 compression block

    // RFC 2104: keys longer than the block are hashed first, shorter ones zero-padded.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36)); // ipad
    inner.extend_from_slice(msg);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(k.iter().map(|b| b ^ 0x5c)); // opad
    outer.extend_from_slice(&sha256(&inner));
    sha256(&outer)
}

/// Hash a key/identifier into the schema's `sha256:<hex>` form (key never in clear).
/// Unsalted (an all-zero HMAC key). Prefer [`key_hash_salted`] for anything emitted from a
/// live capture.
#[must_use]
pub fn key_hash(s: &str) -> String {
    key_hash_salted(&[], s)
}

/// Like [`key_hash`] but KEYS the hash with a per-run `salt` (HMAC-SHA256, salt as the MAC
/// key), so the SAME object key hashes to DIFFERENT values across captures. Within one
/// capture the salt is constant, so same-key correlation (refetch / caching analysis) still
/// works. Across captures, and for offline dictionary or rainbow precomputation against
/// low-entropy keys, the salt defeats it. An empty salt reproduces [`key_hash`]. The salt is
/// held in memory only and is never serialized, so a shared capture cannot be de-salted.
///
/// The output label stays `sha256:` — it names the digest family, which is unchanged, and the
/// schema pins that prefix. The VALUES differ from a plain `SHA256(salt || key)`; salts are
/// per-run so no cross-run comparison depended on them.
#[must_use]
pub fn key_hash_salted(salt: &[u8], key: &str) -> String {
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in hmac_sha256(salt, key.as_bytes()) {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn known_answer_vectors() {
        // FIPS 180-4 / NIST examples.
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Padding-boundary known-answer vectors (the two-block-transition trap):
        // 55 B = one block, zero zero-padding; 56 B forces a 2nd block; 64 B = an
        // exact message block. (Verified against hashlib.)
        assert_eq!(hex(&sha256(&[b'a'; 55])), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
        assert_eq!(hex(&sha256(&[b'a'; 56])), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
        assert_eq!(hex(&sha256(&[b'a'; 64])), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    }

    #[test]
    fn key_hash_format() {
        let h = key_hash("my/object/key");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64, "sha256: + 64 hex chars");
        // Deterministic + distinct.
        assert_eq!(key_hash("a"), key_hash("a"));
        assert_ne!(key_hash("a"), key_hash("b"));
    }

    #[test]
    fn hmac_known_answer_vectors() {
        // RFC 4231 test cases 1, 2, 3 and 6 (the last exercises the >block-size key path,
        // where the key is hashed first). Cross-checked against Python's hmac.
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 20], &[0xdd; 50])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // Block-boundary key (exactly 64 B: no hashing, no padding) and the empty case.
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 64], b"exact-block-key")),
            "cf108052f7d78c15b0b62c3b2e37afb19d015deee03e5069f6dcc4594d2659da"
        );
        assert_eq!(
            hex(&hmac_sha256(b"", b"")),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }

    #[test]
    fn salted_hash_is_a_mac_not_a_secret_prefix_hash() {
        // The salted form must NOT be SHA256(salt || key): that is length-extendable, so one
        // observed (key, hash) pair yields valid hashes for unseen keys. Pin the distinction
        // directly — if someone reverts to the concatenation this fails.
        let salt = b"per-run-salt";
        let concat = {
            let mut b = salt.to_vec();
            b.extend_from_slice(b"k");
            hex(&sha256(&b))
        };
        assert_ne!(key_hash_salted(salt, "k"), format!("sha256:{concat}"), "must be HMAC, not salt||key");
        assert_eq!(key_hash_salted(salt, "k"), format!("sha256:{}", hex(&hmac_sha256(salt, b"k"))));
    }

    #[test]
    fn salt_changes_the_hash_but_stays_stable_within_a_run() {
        let a = key_hash_salted(b"salt-A", "k");
        let b = key_hash_salted(b"salt-B", "k");
        assert_eq!(a, key_hash_salted(b"salt-A", "k"), "same salt + key is stable (within-run correlation holds)");
        assert_ne!(a, b, "a different salt yields a different hash for the same key");
        assert_ne!(a, key_hash("k"), "salting differs from the unsalted hash");
        assert!(a.starts_with("sha256:") && a.len() == 7 + 64);
    }
}

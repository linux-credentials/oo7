use pbkdf2::pbkdf2_hmac;
use sha1::{Digest, Sha1};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const BLOWFISH_BLOCK_SIZE: usize = 8;
pub const PBKDF2_SHA512_KEYSIZE: usize = 56;
pub const PBKDF2_SHA512_ITERATIONS: u32 = 50000;

#[cfg(target_endian = "little")]
fn kwallet_sha1_le(data: &[u8]) -> [u8; 20] {
    const K1: u32 = 0x5a827999;
    const K2: u32 = 0x6ed9eba1;
    const K3: u32 = 0x8f1bbcdc;
    const K4: u32 = 0xca62c1d6;

    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;

    let mut padded = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 16];

        for i in 0..16 {
            w[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => (d ^ (b & (c ^ d)), K1),
                20..=39 => (b ^ c ^ d, K2),
                40..=59 => ((b & c) | (d & (b | c)), K3),
                60..=79 => (b ^ c ^ d, K4),
                _ => unreachable!(),
            };

            let m = if i < 16 {
                w[i]
            } else {
                let tm = w[i & 0x0f] ^ w[(i - 14) & 0x0f] ^ w[(i - 8) & 0x0f] ^ w[(i - 3) & 0x0f];
                w[i & 0x0f] = tm.rotate_left(1);
                w[i & 0x0f]
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(m);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_le_bytes());
    result[4..8].copy_from_slice(&h1.to_le_bytes());
    result[8..12].copy_from_slice(&h2.to_le_bytes());
    result[12..16].copy_from_slice(&h3.to_le_bytes());
    result[16..20].copy_from_slice(&h4.to_le_bytes());

    result
}

/// KWallet's SHA-1 with endianness bug (reads/writes data as LE on
/// little-endian systems)
fn kwallet_sha1(data: &[u8]) -> [u8; 20] {
    #[cfg(target_endian = "little")]
    {
        kwallet_sha1_le(data)
    }

    #[cfg(target_endian = "big")]
    {
        let mut hasher = Sha1::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

fn hash_block_2000(block: &[u8]) -> [u8; 20] {
    let mut hash = Sha1::digest(block).into();
    for _ in 1..2000 {
        hash = Sha1::digest(hash).into();
    }
    hash
}

/// Legacy key derivation: split password into 16-byte blocks, hash each 2000
/// times with SHA1
pub fn derive_key_legacy(password: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return hash_block_2000(&[]).to_vec();
    }

    let blocks: Vec<&[u8]> = password.chunks(16).collect();
    let hashed_blocks: Vec<[u8; 20]> = blocks.iter().map(|b| hash_block_2000(b)).collect();

    match password.len() {
        0..=16 => hashed_blocks[0].to_vec(),
        17..=32 => {
            let mut key = Vec::with_capacity(40);
            key.extend_from_slice(&hashed_blocks[0]);
            key.extend_from_slice(&hashed_blocks[1]);
            key
        }
        33..=48 => {
            let mut key = Vec::with_capacity(56);
            key.extend_from_slice(&hashed_blocks[0]);
            key.extend_from_slice(&hashed_blocks[1]);
            key.extend_from_slice(&hashed_blocks[2][..16]);
            key
        }
        _ => {
            let mut key = Vec::with_capacity(56);
            for block in &hashed_blocks[..4] {
                key.extend_from_slice(&block[..14]);
            }
            key
        }
    }
}

/// Switch endianness (swap every 4 bytes) for legacy Blowfish-ECB
pub fn switch_endianness(data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(4) {
        return Err(Error::InvalidDataStructure);
    }

    Ok(data
        .chunks_exact(4)
        .flat_map(|chunk| chunk.iter().rev().copied())
        .collect())
}

/// PBKDF2-SHA512 key derivation with 50000 iterations
pub fn derive_key_pbkdf2_sha512(
    password: &[u8],
    salt: &[u8],
) -> Zeroizing<[u8; PBKDF2_SHA512_KEYSIZE]> {
    let mut key = Zeroizing::new([0u8; PBKDF2_SHA512_KEYSIZE]);
    pbkdf2_hmac::<Sha512>(password, salt, PBKDF2_SHA512_ITERATIONS, &mut *key);
    key
}

/// Decrypt with Blowfish-CBC (zero IV)
pub fn decrypt_blowfish_cbc(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    use cipher::{BlockDecryptMut, KeyIvInit};

    type BlowfishCbc = cbc::Decryptor<blowfish::Blowfish>;

    let cipher = BlowfishCbc::new_from_slices(key, &[0u8; BLOWFISH_BLOCK_SIZE])
        .map_err(|_| Error::DecryptionFailed)?;

    let mut decrypted = encrypted.to_vec();
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut decrypted)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(decrypted)
}

/// Decrypt with Blowfish-ECB (legacy format)
pub fn decrypt_blowfish_ecb(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    use cipher::{BlockDecryptMut, KeyInit};

    type BlowfishEcb = ecb::Decryptor<blowfish::Blowfish>;

    let cipher = BlowfishEcb::new_from_slice(key).map_err(|_| Error::DecryptionFailed)?;

    let mut decrypted = encrypted.to_vec();
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut decrypted)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(decrypted)
}

/// Validate SHA-1 hash using KWallet's buggy implementation
fn validate_sha1(data: &[u8], expected_hash: &[u8]) -> Result<()> {
    let computed_hash = kwallet_sha1(data);

    if computed_hash.as_slice() != expected_hash {
        return Err(Error::HashValidationFailed);
    }

    Ok(())
}

/// Compute MD5 hash
pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    md5::compute(data).into()
}

/// Extract wallet data from decrypted payload and validate SHA-1 hash
pub fn extract_wallet_data(decrypted: &[u8]) -> Result<Vec<u8>> {
    if decrypted.len() < BLOWFISH_BLOCK_SIZE + 4 + 20 {
        return Err(Error::InvalidDataStructure);
    }

    let mut offset = BLOWFISH_BLOCK_SIZE;

    let size_bytes: [u8; 4] = decrypted[offset..offset + 4]
        .try_into()
        .map_err(|_| Error::InvalidDataStructure)?;
    let data_size = u32::from_be_bytes(size_bytes) as usize;
    offset += 4;

    if data_size > decrypted.len() - offset - 20 {
        return Err(Error::InvalidDataStructure);
    }

    let wallet_data = &decrypted[offset..offset + data_size];
    let hash_offset = decrypted.len() - 20;
    let stored_hash = &decrypted[hash_offset..];

    validate_sha1(wallet_data, stored_hash)?;

    Ok(wallet_data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kwallet_sha1_matches_cpp() {
        let data = [
            0x00, 0x00, 0x00, 0x12, 0x00, 0x46, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x20,
            0x00, 0x44, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x12, 0x00, 0x50, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6f,
            0x00, 0x72, 0x00, 0x64, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x32, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x08, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x70, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x74, 0x00, 0x74,
            0x00, 0x74, 0x00, 0x74, 0x00, 0x74,
        ];

        let hash = kwallet_sha1(&data);

        let expected = [
            0x26, 0x45, 0xc3, 0x1d, 0x53, 0xa1, 0x98, 0x51, 0x00, 0x15, 0xbc, 0x12, 0x59, 0xf3,
            0xb4, 0x54, 0xcc, 0x99, 0x8d, 0xd1,
        ];

        assert_eq!(hash, expected);
    }
}

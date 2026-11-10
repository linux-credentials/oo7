use openssl::{bn::BigNum, dh::Dh, md::Md, pkey::Id, pkey_ctx::PkeyCtx};
use zeroize::Zeroizing;

pub fn generate_public_key_for_secret_exchange(
    private_key: impl AsRef<[u8]>,
) -> Result<Vec<u8>, oo7::crypto::Error> {
    let private_key_bn = BigNum::from_slice(private_key.as_ref()).unwrap();
    let dh = Dh::from_pqg(
        BigNum::get_rfc3526_prime_1536().unwrap(),
        None,
        BigNum::from_u32(2).unwrap(),
    )?;
    Ok(dh.set_private_key(private_key_bn)?.public_key().to_vec())
}

pub fn generate_aes_key_for_secret_exchange(
    private_key: impl AsRef<[u8]>,
    server_public_key: impl AsRef<[u8]>,
) -> Result<Zeroizing<Vec<u8>>, oo7::crypto::Error> {
    let private_key_bn = BigNum::from_slice(private_key.as_ref()).unwrap();
    let server_public_key_bn = BigNum::from_slice(server_public_key.as_ref()).unwrap();
    let dh = Dh::from_pqg(
        BigNum::get_rfc3526_prime_1536().unwrap(),
        None,
        BigNum::from_u32(2).unwrap(),
    )?;
    let mut common_secret_bytes = Zeroizing::new(
        dh.set_private_key(private_key_bn)?
            .compute_key(&server_public_key_bn)?,
    );

    let mut common_secret_padded = Zeroizing::new(vec![0; 192 - common_secret_bytes.len()]);
    common_secret_padded.append(&mut common_secret_bytes);

    // hkdf
    // input_keying_material
    let ikm = common_secret_padded;

    let mut okm = Zeroizing::new(vec![0; 16]);
    let mut ctx = PkeyCtx::new_id(Id::HKDF).unwrap();
    ctx.derive_init().unwrap();
    ctx.set_hkdf_md(Md::sha256()).unwrap();
    ctx.set_hkdf_key(&ikm).unwrap();
    ctx.derive(Some(okm.as_mut()))
        .expect("hkdf expand should never fail");
    Ok(okm)
}

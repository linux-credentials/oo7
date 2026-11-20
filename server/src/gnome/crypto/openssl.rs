use openssl::{
    bn::{BigNum, BigNumContext},
    dh::Dh,
    md::Md,
    pkey::Id,
    pkey_ctx::PkeyCtx,
};
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
    // Don't use `Dh::compute_key()`: it returns `DH_compute_key()`'s whole
    // buffer, in which OpenSSL has moved the secret to the front and appended
    // zeros for every stripped leading zero byte. Compute the shared secret
    // directly and left-pad it to the length of the prime instead.
    let prime = BigNum::get_rfc3526_prime_1536()?;
    // Same range check as DH_compute_key(): 1 < y < p - 1
    let one = BigNum::from_u32(1)?;
    let mut p_minus_one = BigNum::new()?;
    p_minus_one.checked_sub(&prime, &one)?;
    if server_public_key_bn <= one || server_public_key_bn >= p_minus_one {
        return Err(oo7::crypto::Error::Other(
            "Invalid DH public key".to_owned(),
        ));
    }
    let mut bn_ctx = BigNumContext::new_secure()?;
    let mut common_secret = BigNum::new_secure()?;
    common_secret.mod_exp(&server_public_key_bn, &private_key_bn, &prime, &mut bn_ctx)?;
    let common_secret_padded = Zeroizing::new(common_secret.to_vec_padded(192)?);

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

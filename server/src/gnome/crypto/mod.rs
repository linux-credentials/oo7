#[cfg(feature = "gnome_native_crypto")]
mod native;
#[cfg(feature = "gnome_native_crypto")]
use native::*;

#[cfg(feature = "gnome_openssl_crypto")]
mod openssl;
use oo7::Key;

#[cfg(feature = "gnome_openssl_crypto")]
use self::openssl::*;

pub fn generate_public_key(private_key: &Key) -> Result<Key, oo7::crypto::Error> {
    Ok(Key::new(generate_public_key_for_secret_exchange(
        private_key,
    )?))
}

pub fn generate_aes_key(
    private_key: &Key,
    server_public_key: &Key,
) -> Result<Key, oo7::crypto::Error> {
    Ok(Key::new(
        generate_aes_key_for_secret_exchange(private_key, server_public_key)?.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: [u8; 128] = [
        191, 143, 254, 234, 148, 241, 169, 47, 207, 248, 155, 147, 31, 135, 9, 252, 203, 38, 111,
        153, 120, 220, 173, 131, 233, 139, 1, 243, 247, 232, 70, 77, 196, 244, 247, 67, 232, 254,
        100, 194, 155, 37, 248, 243, 70, 206, 170, 133, 192, 248, 253, 74, 74, 194, 238, 165, 102,
        235, 143, 235, 218, 48, 229, 250, 61, 149, 201, 144, 222, 3, 137, 67, 253, 250, 90, 228,
        209, 56, 237, 242, 250, 100, 156, 123, 104, 67, 175, 211, 113, 52, 152, 107, 69, 13, 70,
        30, 89, 146, 193, 149, 62, 100, 247, 37, 57, 44, 71, 49, 101, 29, 80, 151, 240, 155, 160,
        221, 64, 62, 189, 137, 218, 236, 24, 104, 230, 80, 245, 162,
    ];

    #[test]
    fn private_public_pair() {
        let private_key = Key::new(PRIVATE_KEY.to_vec());
        let client_public_key = Key::new(vec![
            90, 240, 105, 52, 245, 225, 112, 238, 63, 100, 6, 129, 215, 27, 199, 53, 210, 16, 60,
            140, 121, 222, 20, 224, 196, 152, 123, 154, 90, 212, 82, 183, 160, 222, 206, 83, 74,
            110, 121, 218, 76, 194, 34, 71, 194, 230, 224, 31, 24, 169, 58, 157, 181, 207, 104,
            182, 223, 223, 29, 254, 144, 74, 129, 204, 114, 165, 224, 109, 23, 123, 66, 139, 251,
            65, 57, 203, 15, 19, 210, 99, 128, 87, 198, 139, 175, 159, 219, 236, 206, 72, 219, 240,
            169, 220, 93, 148, 166, 176, 153, 89, 164, 13, 56, 145, 246, 167, 238, 221, 190, 117,
            148, 10, 211, 24, 19, 84, 204, 2, 111, 240, 32, 90, 252, 154, 81, 254, 230, 56,
        ]);

        let expected_public_key = &[
            64, 119, 1, 90, 244, 5, 65, 235, 2, 24, 179, 85, 248, 14, 227, 193, 177, 100, 179, 54,
            15, 189, 209, 52, 204, 221, 65, 61, 111, 212, 130, 34, 98, 117, 155, 4, 126, 155, 207,
            67, 101, 221, 64, 126, 4, 246, 123, 85, 242, 214, 123, 95, 182, 66, 154, 54, 30, 133,
            199, 185, 196, 60, 65, 36, 242, 251, 174, 218, 47, 220, 76, 131, 169, 11, 201, 124, 67,
            184, 200, 189, 181, 157, 180, 45, 120, 231, 51, 26, 26, 111, 236, 201, 42, 234, 122,
            58, 235, 3, 115, 245, 159, 243, 214, 146, 235, 13, 84, 45, 243, 162, 89, 23, 50, 70,
            139, 104, 64, 138, 214, 193, 244, 94, 177, 110, 165, 96, 238, 152, 146, 136, 10, 86,
            238, 189, 93, 69, 161, 20, 241, 132, 73, 249, 56, 24, 64, 54, 184, 1, 199, 94, 165, 44,
            113, 111, 81, 237, 4, 220, 44, 117, 18, 49, 229, 241, 248, 234, 195, 190, 65, 200, 233,
            150, 227, 57, 195, 103, 140, 237, 165, 145, 27, 68, 88, 166, 2, 46, 210, 212, 163, 185,
            115, 68,
        ];
        let expected_aes_key = &[
            246, 159, 99, 143, 217, 217, 155, 222, 215, 178, 246, 113, 252, 190, 156, 70,
        ];

        let public_key = generate_public_key(&private_key);
        let aes_key = generate_aes_key(&private_key, &client_public_key);

        assert_eq!(public_key.unwrap().as_ref(), expected_public_key);
        assert_eq!(aes_key.unwrap().as_ref(), expected_aes_key);
    }

    #[test]
    fn aes_key_with_leading_zero_in_shared_secret() {
        // With this peer public key (273^2, a valid group element), the shared
        // secret starts with a zero byte, which has to be kept for HKDF
        let private_key = Key::new(PRIVATE_KEY.to_vec());
        let client_public_key = Key::new(vec![1, 35, 33]);
        let expected_aes_key = &[
            50, 213, 186, 140, 94, 189, 52, 75, 137, 14, 75, 68, 123, 187, 127, 87,
        ];

        let aes_key = generate_aes_key(&private_key, &client_public_key);

        assert_eq!(aes_key.unwrap().as_ref(), expected_aes_key);
    }
}

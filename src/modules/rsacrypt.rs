use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

pub struct RSACrypt;

impl RSACrypt {
    /// ===================================================================
    /// 🔑 從 PEM 檔案載入公鑰
    /// ===================================================================
    pub fn load_public_key(file_path: &str) -> Result<RsaPublicKey, String> {
        RsaPublicKey::read_public_key_pem_file(file_path)
            .map_err(|e| format!("載入公鑰失敗: {}", e))
    }

    /// ===================================================================
    /// 🔑 從 PEM 檔案載入私鑰
    /// ===================================================================
    pub fn load_private_key(file_path: &str) -> Result<RsaPrivateKey, String> {
        RsaPrivateKey::read_pkcs8_pem_file(file_path)
            .map_err(|e| format!("載入私鑰失敗: {}", e))
    }

    /// ===================================================================
    /// 🔒 使用公鑰加密資料
    /// 注意：RSA 只能加密極小量資料 (受限於金鑰長度減去 Padding)。
    /// 2048-bit RSA 搭配 OAEP+SHA256 最多只能加密約 190 Bytes。
    /// ===================================================================
    pub fn encrypt(pub_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut rng = OsRng;
        let padding = Oaep::new::<Sha256>();
        
        pub_key
            .encrypt(&mut rng, padding, data)
            .map_err(|e| format!("RSA 加密失敗: {}", e))
    }

    /// ===================================================================
    /// 🔓 使用私鑰解密資料
    /// ===================================================================
    pub fn decrypt(priv_key: &RsaPrivateKey, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        let padding = Oaep::new::<Sha256>();
        
        priv_key
            .decrypt(padding, encrypted_data)
            .map_err(|e| format!("RSA 解密失敗: {}", e))
    }

    /// ===================================================================
    /// ✍️ 使用私鑰對資料進行簽章 (PKCS#1 v1.5 + SHA256)
    /// ===================================================================
    pub fn sign(priv_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, String> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{Signer, SignatureEncoding};
        
        let signing_key = SigningKey::<Sha256>::new_unprefixed(priv_key.clone());
        let sig = signing_key.sign(data);
        Ok(sig.to_vec())
    }

    /// ===================================================================
    /// 🛡️ 使用公鑰驗證簽章
    /// ===================================================================
    pub fn verify(pub_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> Result<(), String> {
        use rsa::pkcs1v15::{VerifyingKey, Signature};
        use rsa::signature::Verifier;
        
        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(pub_key.clone());
        let sig = Signature::try_from(signature).map_err(|e| format!("無效的簽章格式: {}", e))?;
        verifying_key.verify(data, &sig).map_err(|e| format!("驗章失敗: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::keygen::KeyGen;
    use std::fs;

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let mut priv_path = std::env::temp_dir();
        priv_path.push("test_rsa_enc_dec_priv.pem");
        let mut pub_path = std::env::temp_dir();
        pub_path.push("test_rsa_enc_dec_pub.pem");

        let priv_str = priv_path.to_str().unwrap();
        let pub_str = pub_path.to_str().unwrap();

        // 產生測試用金鑰對 (為求快速測試使用 2048 bits)
        KeyGen::generate_rsa_key_pair(2048, priv_str, pub_str).unwrap();

        let pub_key = RSACrypt::load_public_key(pub_str).unwrap();
        let priv_key = RSACrypt::load_private_key(priv_str).unwrap();

        let original_data = b"Hello, RSA Asymmetric Encryption!";
        
        let encrypted = RSACrypt::encrypt(&pub_key, original_data).unwrap();
        let decrypted = RSACrypt::decrypt(&priv_key, &encrypted).unwrap();

        assert_eq!(original_data.as_slice(), decrypted.as_slice());

        let _ = fs::remove_file(priv_path);
        let _ = fs::remove_file(pub_path);
    }

    #[test]
    fn test_rsa_sign_verify() {
        let mut priv_path = std::env::temp_dir();
        priv_path.push("test_rsa_sign_priv.pem");
        let mut pub_path = std::env::temp_dir();
        pub_path.push("test_rsa_sign_pub.pem");

        let priv_str = priv_path.to_str().unwrap();
        let pub_str = pub_path.to_str().unwrap();

        KeyGen::generate_rsa_key_pair(2048, priv_str, pub_str).unwrap();

        let pub_key = RSACrypt::load_public_key(pub_str).unwrap();
        let priv_key = RSACrypt::load_private_key(priv_str).unwrap();

        let original_data = b"Data to be signed!";
        
        let signature = RSACrypt::sign(&priv_key, original_data).unwrap();
        let is_valid = RSACrypt::verify(&pub_key, original_data, &signature);
        assert!(is_valid.is_ok());

        let _ = fs::remove_file(priv_path);
        let _ = fs::remove_file(pub_path);
    }
}
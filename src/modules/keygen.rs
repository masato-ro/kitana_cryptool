use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    traits::PublicKeyParts,
    BigUint, RsaPrivateKey, RsaPublicKey,
};

pub struct KeyGen;

impl KeyGen {
    /// ===================================================================
    /// 🔑 1. 金鑰對產生核心 (Pure Rust 實作)
    /// ===================================================================
    pub fn generate_rsa_key_pair(
        bits: usize,
        private_path: &str,
        public_path: &str,
    ) -> Result<(), String> {
        if bits < 1024 {
            return Err("Key size must be at least 1024 bits".into());
        }

        let mut rng = OsRng;
        
        // 產生 RSA 私鑰
        let priv_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| format!("Failed to generate RSA key: {}", e))?;
            
        // 推導出公鑰
        let pub_key = RsaPublicKey::from(&priv_key);

        // 寫出 PKCS#8 格式的私鑰 (.pem)
        priv_key
            .write_pkcs8_pem_file(private_path, LineEnding::LF)
            .map_err(|e| format!("Failed to write private key: {}", e))?;

        // 寫出 X.509 (SPKI) 格式的公鑰 (.pem)
        pub_key
            .write_public_key_pem_file(public_path, LineEnding::LF)
            .map_err(|e| format!("Failed to write public key: {}", e))?;

        Ok(())
    }

    /// ===================================================================
    /// 🔑 2. 從檔案載入私鑰
    /// ===================================================================
    pub fn load_private_key_from_file(file_path: &str) -> Result<RsaPrivateKey, String> {
        RsaPrivateKey::read_pkcs8_pem_file(file_path)
            .map_err(|e| format!("Failed to load private key from {}: {}", file_path, e))
    }

    /// ===================================================================
    /// 🔑 3. 【純 Rust 現代化 API】的 OpenSSH 公鑰生成函式
    /// ===================================================================
    pub fn generate_openssh_public_key(pkey: &RsaPrivateKey, comment: &str) -> String {
        let n = pkey.n();
        let e = pkey.e();

        let mut blob = Vec::new();

        // encode_string("ssh-rsa")
        let type_str = "ssh-rsa";
        blob.extend_from_slice(&(type_str.len() as u32).to_be_bytes());
        blob.extend_from_slice(type_str.as_bytes());

        // encode_mpint(e)
        blob.extend_from_slice(&Self::encode_mpint(e));

        // encode_mpint(n)
        blob.extend_from_slice(&Self::encode_mpint(n));

        // 🛠️ 【密碼學專用：標準 Rust Base64 轉換】
        let b64 = general_purpose::STANDARD.encode(&blob);

        let mut final_key = format!("ssh-rsa {}", b64);
        if !comment.is_empty() {
            final_key.push(' ');
            final_key.push_str(comment);
        }

        final_key
    }

    /// ===================================================================
    /// 🎯 【終極防禦】：原生 Rust 萬用大端序轉換晶片 (取代 C++ htonl)
    /// ===================================================================
    fn encode_mpint(bn: &BigUint) -> Vec<u8> {
        let raw = bn.to_bytes_be();
        if raw.is_empty() || (raw.len() == 1 && raw[0] == 0) {
            return vec![0, 0, 0, 0]; // 若為 0 則回傳長度 0 的 mpint
        }

        // SSH 協議規定：若第一位元為 1 (大於等於 0x80)，為了避免被判讀為負數，必須在開頭補上 0x00
        let prepend_zero = (raw[0] & 0x80) != 0;
        let len = raw.len() as u32 + if prepend_zero { 1 } else { 0 };

        let mut result = Vec::with_capacity(4 + len as usize);
        // 直接使用 .to_be_bytes() 代替複雜的 bit shift
        result.extend_from_slice(&len.to_be_bytes());
        if prepend_zero {
            result.push(0x00);
        }
        result.extend_from_slice(&raw);
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_file_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(name);
        path
    }

    #[test]
    fn test_generate_and_load_rsa_keys() {
        let priv_path = temp_file_path("test_id_rsa.pem");
        let pub_path = temp_file_path("test_id_rsa.pub.pem");

        // 1. 測試：產生 1024-bit RSA 金鑰對 (為求測試快速使用 1024 bits)
        let res = KeyGen::generate_rsa_key_pair(1024, priv_path.to_str().unwrap(), pub_path.to_str().unwrap());
        assert!(res.is_ok(), "金鑰產生失敗: {:?}", res.err());

        // 2. 測試：讀取剛剛寫入的私鑰
        let pkey_res = KeyGen::load_private_key_from_file(priv_path.to_str().unwrap());
        assert!(pkey_res.is_ok(), "私鑰讀取失敗");
        let pkey = pkey_res.unwrap();

        // 3. 測試：產生 OpenSSH 格式的公鑰
        let openssh_pub = KeyGen::generate_openssh_public_key(&pkey, "kitana-user");
        assert!(openssh_pub.starts_with("ssh-rsa "), "OpenSSH 公鑰格式錯誤");
        assert!(openssh_pub.ends_with(" kitana-user"), "OpenSSH 公鑰未包含正確的 Comment");

        // 4. 清理測試產生的暫存檔案
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
    }
}
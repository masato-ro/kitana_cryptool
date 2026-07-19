use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    BigUint, Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

pub struct RSACrypt;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

impl RSACrypt {
    /// ===================================================================
    /// 🔑 從 PEM 檔案載入公鑰
    /// ===================================================================
    pub fn load_public_key(file_path: &str) -> Result<RsaPublicKey, String> {
        if let Ok(pub_key) = RsaPublicKey::read_public_key_pem_file(file_path) {
            return Ok(pub_key);
        }

        let contents = std::fs::read_to_string(file_path)
            .map_err(|e| format!("載入公鑰失敗: {}", e))?;
        Self::parse_openssh_public_key(&contents)
            .map_err(|e| format!("載入公鑰失敗: {}", e))
    }

    fn parse_openssh_public_key(contents: &str) -> Result<RsaPublicKey, String> {
        let trimmed = contents.trim();
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 2 {
            return Err("OpenSSH public key format is invalid".into());
        }

        let key_type = fields[0];
        if key_type != "ssh-rsa" {
            return Err(format!("Unsupported OpenSSH key type: {}", key_type));
        }

        let key_blob = general_purpose::STANDARD.decode(fields[1])
            .map_err(|e| format!("Failed to decode OpenSSH key blob: {}", e))?;

        let mut offset = 0usize;
        let parsed_type = Self::read_string(&key_blob, &mut offset)?;
        if String::from_utf8_lossy(&parsed_type) != "ssh-rsa" {
            return Err("OpenSSH key blob does not contain an RSA public key".into());
        }

        let exponent_bytes = Self::read_mpint(&key_blob, &mut offset)?;
        let modulus_bytes = Self::read_mpint(&key_blob, &mut offset)?;

        let exponent = BigUint::from_bytes_be(&exponent_bytes);
        let modulus = BigUint::from_bytes_be(&modulus_bytes);

        RsaPublicKey::new(modulus, exponent)
            .map_err(|e| format!("Failed to construct RSA public key from OpenSSH data: {}", e))
    }

    fn read_string(blob: &[u8], offset: &mut usize) -> Result<Vec<u8>, String> {
        if *offset + 4 > blob.len() {
            return Err("Truncated OpenSSH string length".into());
        }
        let length = u32::from_be_bytes(blob[*offset..*offset + 4].try_into().unwrap()) as usize;
        *offset += 4;
        if *offset + length > blob.len() {
            return Err("Truncated OpenSSH string payload".into());
        }
        let data = blob[*offset..*offset + length].to_vec();
        *offset += length;
        Ok(data)
    }

    fn read_mpint(blob: &[u8], offset: &mut usize) -> Result<Vec<u8>, String> {
        if *offset + 4 > blob.len() {
            return Err("Truncated OpenSSH mpint length".into());
        }
        let length = u32::from_be_bytes(blob[*offset..*offset + 4].try_into().unwrap()) as usize;
        *offset += 4;
        if *offset + length > blob.len() {
            return Err("Truncated OpenSSH mpint payload".into());
        }
        let data = blob[*offset..*offset + length].to_vec();
        *offset += length;
        Ok(data)
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

    /// ===================================================================
    /// 📦 Hybrid 加密 (AES-256-CBC + RSA) - 純位元組資料
    /// ===================================================================
    pub fn hybrid_encrypt_bytes(pub_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut rng = OsRng;
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);

        let len = data.len();
        let padded_len = len + 16 - (len % 16);
        let mut buf = vec![0u8; padded_len];
        buf[..len].copy_from_slice(data);

        let enc = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = enc.encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buf, len)
            .map_err(|e| format!("AES Encrypt failed: {:?}", e))?;

        let mut key_iv = Vec::with_capacity(48);
        key_iv.extend_from_slice(&key);
        key_iv.extend_from_slice(&iv);

        let rsa_enc_key = Self::encrypt(pub_key, &key_iv)?;
        let rsa_len = rsa_enc_key.len() as u16;

        let mut payload = Vec::with_capacity(2 + rsa_enc_key.len() + ciphertext.len());
        payload.extend_from_slice(&rsa_len.to_be_bytes());
        payload.extend_from_slice(&rsa_enc_key);
        payload.extend_from_slice(ciphertext);

        Ok(payload)
    }

    /// ===================================================================
    /// 📦 Hybrid 解密 (AES-256-CBC + RSA) - 純位元組資料
    /// ===================================================================
    pub fn hybrid_decrypt_bytes(priv_key: &RsaPrivateKey, payload: &[u8]) -> Result<Vec<u8>, String> {
        if payload.len() < 2 {
            return Err("Invalid payload format (too short).".into());
        }
        let rsa_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + rsa_len {
            return Err("Invalid payload format (corrupted RSA block).".into());
        }

        let rsa_enc_key = &payload[2..2 + rsa_len];
        let aes_ciphertext = &payload[2 + rsa_len..];

        let key_iv = Self::decrypt(priv_key, rsa_enc_key)?;
        if key_iv.len() != 48 {
            return Err("Decrypted AES key/IV has invalid length.".into());
        }

        let dec_key = &key_iv[0..32];
        let dec_iv = &key_iv[32..48];

        let mut buf = aes_ciphertext.to_vec();
        let dec = Aes256CbcDec::new_from_slices(dec_key, dec_iv).unwrap();
        let plaintext = dec.decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|e| format!("AES Decrypt failed: {:?}", e))?;

        Ok(plaintext.to_vec())
    }

    /// ===================================================================
    /// 📁 Hybrid 串流加密 (AES-256-CBC + RSA) - 純檔案
    /// ===================================================================
    pub fn hybrid_encrypt_file(
        pub_key: &RsaPublicKey,
        in_path: &str,
        out_path: &str,
        progress_callback: Option<Box<dyn Fn(u32) + Send>>,
        cancel_flag: Option<Arc<AtomicBool>>,
    ) -> Result<(), String> {
        let mut in_file = File::open(in_path).map_err(|e| format!("Cannot open input file: {}", e))?;
        let mut out_file = File::create(out_path).map_err(|e| format!("Cannot create output file: {}", e))?;

        let total_bytes = in_file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut processed_bytes = 0u64;
        let mut last_percent = 0u32;

        let mut rng = OsRng;
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);

        let mut key_iv = Vec::with_capacity(48);
        key_iv.extend_from_slice(&key);
        key_iv.extend_from_slice(&iv);

        let rsa_enc_key = Self::encrypt(pub_key, &key_iv)?;
        let rsa_len = rsa_enc_key.len() as u16;

        out_file.write_all(&rsa_len.to_be_bytes()).map_err(|e| format!("Write failed: {}", e))?;
        out_file.write_all(&rsa_enc_key).map_err(|e| format!("Write failed: {}", e))?;

        let mut enc = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
        let mut read_buf = [0u8; 4096];

        loop {
            if let Some(ref flag) = cancel_flag {
                if flag.load(Ordering::Relaxed) {
                    return Err("Operation cancelled.".to_string());
                }
            }

            let bytes_read = in_file.read(&mut read_buf).map_err(|e| format!("Read failed: {}", e))?;
            if bytes_read == 0 { break; }

            processed_bytes += bytes_read as u64;
            if let Some(ref callback) = progress_callback {
                if total_bytes > 0 {
                    let percent = ((processed_bytes * 100) / total_bytes) as u32;
                    if percent > last_percent {
                        callback(percent.min(100));
                        last_percent = percent;
                    }
                }
            }

            if bytes_read < 4096 {
                let mut final_buf = vec![0u8; bytes_read + 16];
                final_buf[..bytes_read].copy_from_slice(&read_buf[..bytes_read]);
                let ciphertext = enc.encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut final_buf, bytes_read)
                    .map_err(|e| format!("Encrypt failed: {:?}", e))?;
                out_file.write_all(ciphertext).map_err(|e| format!("Write failed: {}", e))?;
                if let Some(ref callback) = progress_callback {
                    callback(100);
                }
                return Ok(());
            } else {
                for chunk in read_buf.chunks_exact_mut(16) {
                    let block: &mut [u8; 16] = chunk.try_into().unwrap();
                    enc.encrypt_block_mut(block.into());
                }
                out_file.write_all(&read_buf).map_err(|e| format!("Write failed: {}", e))?;
            }
        }

        let mut empty_pad = [0u8; 16];
        let ciphertext = enc.encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut empty_pad, 0)
            .map_err(|e| format!("Encrypt pad failed: {:?}", e))?;
        out_file.write_all(ciphertext).map_err(|e| format!("Write failed: {}", e))?;

        if let Some(ref callback) = progress_callback {
            callback(100);
        }
        Ok(())
    }

    /// ===================================================================
    /// 📁 Hybrid 串流解密 (AES-256-CBC + RSA) - 純檔案
    /// ===================================================================
    pub fn hybrid_decrypt_file(
        priv_key: &RsaPrivateKey,
        in_path: &str,
        out_path: &str,
        progress_callback: Option<Box<dyn Fn(u32) + Send>>,
        cancel_flag: Option<Arc<AtomicBool>>,
    ) -> Result<(), String> {
        let mut in_file = File::open(in_path).map_err(|e| format!("Cannot open input file: {}", e))?;
        let mut out_file = File::create(out_path).map_err(|e| format!("Cannot create output file: {}", e))?;

        let total_bytes = in_file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut processed_bytes = 0u64;
        let mut last_percent = 0u32;

        let mut len_buf = [0u8; 2];
        in_file.read_exact(&mut len_buf).map_err(|_| "Failed to read RSA length".to_string())?;
        let rsa_len = u16::from_be_bytes(len_buf) as usize;

        let mut rsa_enc_key = vec![0u8; rsa_len];
        in_file.read_exact(&mut rsa_enc_key).map_err(|_| "Failed to read RSA key block".to_string())?;

        let header_len = 2 + rsa_len as u64;
        let encrypted_payload_len = if total_bytes > header_len { total_bytes - header_len } else { 0 };

        let key_iv = Self::decrypt(priv_key, &rsa_enc_key)?;
        if key_iv.len() != 48 {
            return Err("Invalid decrypted AES key length".into());
        }

        let dec_key = &key_iv[0..32];
        let dec_iv = &key_iv[32..48];

        let mut dec = Aes256CbcDec::new_from_slices(dec_key, dec_iv).unwrap();
        let mut read_buf = [0u8; 4096];
        let mut ciphertext_accumulator = Vec::new();

        loop {
            if let Some(ref flag) = cancel_flag {
                if flag.load(Ordering::Relaxed) {
                    return Err("Operation cancelled.".to_string());
                }
            }

            let bytes_read = in_file.read(&mut read_buf).map_err(|e| format!("Read failed: {}", e))?;
            if bytes_read == 0 { break; }

            processed_bytes += bytes_read as u64;
            if let Some(ref callback) = progress_callback {
                if encrypted_payload_len > 0 {
                    let percent = ((processed_bytes * 100) / encrypted_payload_len) as u32;
                    if percent > last_percent {
                        callback(percent.min(100));
                        last_percent = percent;
                    }
                }
            }

            ciphertext_accumulator.extend_from_slice(&read_buf[..bytes_read]);

            if ciphertext_accumulator.len() > 16 {
                let total_len = ciphertext_accumulator.len();
                let remainder = total_len % 16;
                let drain_len = if remainder == 0 { total_len - 16 } else { total_len - remainder - 16 };

                if drain_len > 0 {
                    let mut ready_to_dec: Vec<u8> = ciphertext_accumulator.drain(..drain_len).collect();
                    for chunk in ready_to_dec.chunks_exact_mut(16) {
                        let block: &mut [u8; 16] = chunk.try_into().unwrap();
                        dec.decrypt_block_mut(block.into());
                    }
                    out_file.write_all(&ready_to_dec).map_err(|e| format!("Write failed: {}", e))?;
                }
            }
        }

        if !ciphertext_accumulator.is_empty() {
            let remainder = ciphertext_accumulator.len() % 16;
            if remainder > 0 {
                let valid_len = ciphertext_accumulator.len() - remainder;
                ciphertext_accumulator.truncate(valid_len);
            }

            if !ciphertext_accumulator.is_empty() {
                let plaintext = dec.decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut ciphertext_accumulator)
                    .map_err(|_| "Decrypt padded failed (Wrong key or corrupted file)".to_string())?;
                out_file.write_all(plaintext).map_err(|e| format!("Write failed: {}", e))?;
            }
        }

        if let Some(ref callback) = progress_callback {
            callback(100);
        }
        Ok(())
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
        KeyGen::generate_rsa_key_pair(2048, priv_str, pub_str, Some("kitana-test"), crate::modules::keygen::PublicKeyOutputFormat::OpenSsh).unwrap();

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

        KeyGen::generate_rsa_key_pair(2048, priv_str, pub_str, Some("kitana-test"), crate::modules::keygen::PublicKeyOutputFormat::OpenSsh).unwrap();

        let pub_key = RSACrypt::load_public_key(pub_str).unwrap();
        let priv_key = RSACrypt::load_private_key(priv_str).unwrap();

        let original_data = b"Data to be signed!";
        
        let signature = RSACrypt::sign(&priv_key, original_data).unwrap();
        let is_valid = RSACrypt::verify(&pub_key, original_data, &signature);
        assert!(is_valid.is_ok());

        let _ = fs::remove_file(priv_path);
        let _ = fs::remove_file(pub_path);
    }

    #[test]
    fn test_hybrid_encrypt_decrypt_large_data() {
        let mut priv_path = std::env::temp_dir();
        priv_path.push("test_hybrid_priv.pem");
        let mut pub_path = std::env::temp_dir();
        pub_path.push("test_hybrid_pub.pem");

        let priv_str = priv_path.to_str().unwrap();
        let pub_str = pub_path.to_str().unwrap();

        // 產生測試用金鑰對
        KeyGen::generate_rsa_key_pair(2048, priv_str, pub_str, Some("kitana-test"), crate::modules::keygen::PublicKeyOutputFormat::OpenSsh).unwrap();

        let pub_key = RSACrypt::load_public_key(pub_str).unwrap();
        let priv_key = RSACrypt::load_private_key(priv_str).unwrap();

        // 建立超長測試資料 (長度遠大於 190 Bytes，純 RSA 無法直接加密)
        let original_data = "This is a super secret large payload! ".repeat(50);
        let data_bytes = original_data.as_bytes();
        assert!(data_bytes.len() > 190, "Test data is not long enough to prove Hybrid bypassing RSA limit");

        let payload = RSACrypt::hybrid_encrypt_bytes(&pub_key, data_bytes).unwrap();
        let decrypted_bytes = RSACrypt::hybrid_decrypt_bytes(&priv_key, &payload).unwrap();
        let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();

        assert_eq!(original_data, decrypted_string, "Decrypted data does not match the original payload!");

        let _ = fs::remove_file(priv_path);
        let _ = fs::remove_file(pub_path);
    }

    #[test]
    fn test_hybrid_encrypt_decrypt_file() {
        let mut priv_path = std::env::temp_dir();
        priv_path.push("test_hybrid_file_priv.pem");
        let mut pub_path = std::env::temp_dir();
        pub_path.push("test_hybrid_file_pub.pem");

        let priv_str = priv_path.to_str().unwrap();
        let pub_str = pub_path.to_str().unwrap();

        KeyGen::generate_rsa_key_pair(2048, priv_str, pub_str, Some("kitana-test"), crate::modules::keygen::PublicKeyOutputFormat::OpenSsh).unwrap();
        let pub_key = RSACrypt::load_public_key(pub_str).unwrap();
        let priv_key = RSACrypt::load_private_key(priv_str).unwrap();

        let in_file = std::env::temp_dir().join("test_hybrid_in.bin");
        let enc_file = std::env::temp_dir().join("test_hybrid_enc.bin");
        let dec_file = std::env::temp_dir().join("test_hybrid_dec.bin");

        let mut original_data = vec![0u8; 10000];
        for i in 0..original_data.len() {
            original_data[i] = (i % 256) as u8;
        }
        fs::write(&in_file, &original_data).unwrap();

        RSACrypt::hybrid_encrypt_file(&pub_key, in_file.to_str().unwrap(), enc_file.to_str().unwrap(), None, None).unwrap();
        RSACrypt::hybrid_decrypt_file(&priv_key, enc_file.to_str().unwrap(), dec_file.to_str().unwrap(), None, None).unwrap();

        let decrypted_data = fs::read(&dec_file).unwrap();
        assert_eq!(original_data, decrypted_data);

        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
        let _ = fs::remove_file(&in_file);
        let _ = fs::remove_file(&enc_file);
        let _ = fs::remove_file(&dec_file);
    }
}
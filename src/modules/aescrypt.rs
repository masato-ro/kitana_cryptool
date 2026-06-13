use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32; // 256 bits for AES-256
const IV_LEN: usize = 16;  // 128 bits for AES-CBC

#[cfg(not(test))]
const PBKDF2_ITER: u32 = 100_000; // 正式環境維持 10 萬次
#[cfg(test)]
const PBKDF2_ITER: u32 = 100;     // 測試環境降低次數

const BUFFER_SIZE: usize = 4096;

pub type ProgressCallback = Box<dyn Fn(u32) + Send>;

pub struct AESCrypt;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

impl AESCrypt {
    /// 加密檔案
    pub fn encrypt_file_with_progress(
        in_file: &str,
        out_file: &str,
        password: &str,
        progress_callback: Option<ProgressCallback>,
        cancel_flag: Option<Arc<AtomicBool>>,
    ) -> Result<(), String> {
        Self::crypt_file(in_file, out_file, password, true, progress_callback, cancel_flag)
    }

    /// 解密檔案
    pub fn decrypt_file_with_progress(
        in_file: &str,
        out_file: &str,
        password: &str,
        progress_callback: Option<ProgressCallback>,
        cancel_flag: Option<Arc<AtomicBool>>,
    ) -> Result<(), String> {
        Self::crypt_file(in_file, out_file, password, false, progress_callback, cancel_flag)
    }

    /// 加密/解密檔案的核心函數
    fn crypt_file(
        in_file: &str,
        out_file: &str,
        password: &str,
        encrypt: bool,
        progress_callback: Option<ProgressCallback>,
        cancel_flag: Option<Arc<AtomicBool>>,
    ) -> Result<(), String> {
        use cipher::block_padding::Pkcs7;

        // 1️⃣ 打開檔案
        let mut in_handle = File::open(in_file).map_err(|e| format!("無法打開輸入檔案: {}", e))?;
        let mut out_handle = File::create(out_file).map_err(|e| format!("無法創建輸出檔案: {}", e))?;

        // 2️⃣ 獲取輸入檔案總長度
        let total_bytes = fs::metadata(in_file).map(|m| m.len()).unwrap_or(0);
        let mut processed_bytes: u64 = 0;
        let mut last_percent: u32 = 0;

        // 3️⃣ 處理 Salt
        let salt = if encrypt {
            let mut salt = [0u8; SALT_LEN];
            getrandom::getrandom(&mut salt).map_err(|e| format!("生成 Salt 失敗: {}", e))?;
            out_handle.write_all(&salt).map_err(|e| format!("寫入 Salt 失敗: {}", e))?;
            salt
        } else {
            let mut salt = [0u8; SALT_LEN];
            in_handle.read_exact(&mut salt).map_err(|e| format!("讀取 Salt 失敗: {}", e))?;
            processed_bytes += SALT_LEN as u64;
            salt
        };

        // 4️⃣ PBKDF2 金鑰衍生
        let mut key_iv = vec![0u8; KEY_LEN + IV_LEN];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITER, &mut key_iv);
        let key = &key_iv[..KEY_LEN];
        let iv = &key_iv[KEY_LEN..KEY_LEN + IV_LEN];

        // 5️⃣ 串流緩衝區配置
        let mut read_buf = vec![0u8; BUFFER_SIZE];

        if encrypt {
            let mut enc = Aes256CbcEnc::new_from_slices(key, iv)
                .map_err(|e| format!("初始化加密器失敗: {}", e))?;
            
            loop {
                if let Some(ref flag) = cancel_flag {
                    if flag.load(Ordering::Relaxed) { return Err("Operation cancelled.".to_string()); }
                }

                let bytes_read = in_handle.read(&mut read_buf).map_err(|e| format!("讀取失敗: {}", e))?;
                if bytes_read == 0 { break; }

                processed_bytes += bytes_read as u64;
                if let Some(ref callback) = progress_callback {
                    if total_bytes > 0 {
                        let percent = ((processed_bytes * 100) / total_bytes) as u32;
                        if percent > last_percent { callback(percent.min(100)); last_percent = percent; }
                    }
                }

                if bytes_read < BUFFER_SIZE {
                    let mut final_buf = vec![0u8; bytes_read + 16]; 
                    final_buf[..bytes_read].copy_from_slice(&read_buf[..bytes_read]);
                    
                    let ciphertext = enc.encrypt_padded_mut::<Pkcs7>(&mut final_buf, bytes_read)
                        .map_err(|e| format!("加密結尾失敗: {:?}", e))?;
                    
                    out_handle.write_all(ciphertext).map_err(|e| format!("寫入失敗: {}", e))?;
                    if let Some(callback) = progress_callback { callback(100); }
                    return Ok(());
                } else {
                    for chunk in read_buf.chunks_exact_mut(16) {
                        let block: &mut [u8; 16] = chunk.try_into().unwrap();
                        enc.encrypt_block_mut(block.into());
                    }
                    out_handle.write_all(&read_buf).map_err(|e| format!("寫入失敗: {}", e))?;
                }
            }

            let mut empty_pad = [0u8; 16];
            let ciphertext = enc.encrypt_padded_mut::<Pkcs7>(&mut empty_pad, 0)
                .map_err(|e| format!("加密結尾失敗: {:?}", e))?;
            out_handle.write_all(ciphertext).map_err(|e| format!("寫入失敗: {}", e))?;

       } else {
            let mut dec = Aes256CbcDec::new_from_slices(key, iv)
                .map_err(|e| format!("初始化解密器失敗: {}", e))?;
            
            // 建立累積緩衝區
            let mut ciphertext_accumulator = Vec::new();

            loop {
                if let Some(ref flag) = cancel_flag {
                    if flag.load(Ordering::Relaxed) { return Err("Operation cancelled.".to_string()); }
                }

                let bytes_read = in_handle.read(&mut read_buf).map_err(|e| format!("讀取失敗: {}", e))?;
                if bytes_read == 0 { break; }

                processed_bytes += bytes_read as u64;
                if let Some(ref callback) = progress_callback {
                    if total_bytes > 0 {
                        let percent = ((processed_bytes * 100) / total_bytes) as u32;
                        if percent > last_percent { callback(percent.min(100)); last_percent = percent; }
                    }
                }

                ciphertext_accumulator.extend_from_slice(&read_buf[..bytes_read]);

                // 為了安全剔除 Padding，永遠在水庫裡保留最後至少 16 位元組
                if ciphertext_accumulator.len() > 16 {
                    let total_len = ciphertext_accumulator.len();
                    let remainder = total_len % 16;
                    
                    // 確保留下來的尾巴一定是 16 的倍數（16 或 32...）
                    let drain_len = if remainder == 0 {
                        total_len - 16
                    } else {
                        total_len - remainder - 16
                    };

                    if drain_len > 0 {
                        let mut ready_to_dec: Vec<u8> = ciphertext_accumulator.drain(..drain_len).collect();
                        for chunk in ready_to_dec.chunks_exact_mut(16) {
                            let block: &mut [u8; 16] = chunk.try_into().unwrap();
                            dec.decrypt_block_mut(block.into());
                        }
                        out_handle.write_all(&ready_to_dec).map_err(|e| format!("寫入失敗: {}", e))?;
                    }
                }
            }

            // 進入最終結尾處理
            if !ciphertext_accumulator.is_empty() {
                // 強行對齊舊 C++ 的非標準長度密文
                // 如果最後水庫長度不是 16 的倍數，直接把不滿 16 的無效尾巴（垃圾資料）給砍掉
                let remainder = ciphertext_accumulator.len() % 16;
                if remainder > 0 {
                    let valid_len = ciphertext_accumulator.len() - remainder;
                    ciphertext_accumulator.truncate(valid_len);
                }

                // 如果砍完後還有有效的密文塊，才進行 PKCS7 解填充
                if !ciphertext_accumulator.is_empty() {
                    let plaintext = dec.decrypt_padded_mut::<Pkcs7>(&mut ciphertext_accumulator)
                        .map_err(|_| "解密失敗：密碼錯誤或檔案已損毀 (Padding Error)".to_string())?;

                    out_handle.write_all(plaintext).map_err(|e| format!("寫入失敗: {}", e))?;
                }
            }
        }

        if let Some(callback) = progress_callback { callback(100); }
        Ok(())
    }
} 

// 獨立且待在最底部的測試模組
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
    fn test_encrypt_decrypt() {
        let in_file = temp_file_path("test_in.txt");
        let enc_file = temp_file_path("test_enc.bin");
        let dec_file = temp_file_path("test_dec.txt");
        let password = "super_secret_password";
        let original_data = b"Hello, this is a test for AES-256-CBC encryption and decryption!";

        fs::write(&in_file, original_data).unwrap();

        AESCrypt::encrypt_file_with_progress(
            in_file.to_str().unwrap(),
            enc_file.to_str().unwrap(),
            password,
            None,
            None,
        ).unwrap();

        AESCrypt::decrypt_file_with_progress(
            enc_file.to_str().unwrap(),
            dec_file.to_str().unwrap(),
            password,
            None,
            None,
        ).unwrap();

        let decrypted_data = fs::read(&dec_file).unwrap();
        assert_eq!(original_data.as_ref(), decrypted_data.as_slice());

        let _ = fs::remove_file(&in_file);
        let _ = fs::remove_file(&enc_file);
        let _ = fs::remove_file(&dec_file);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let in_file = temp_file_path("test_wrong_in.txt");
        let enc_file = temp_file_path("test_wrong_enc.bin");
        let dec_file = temp_file_path("test_wrong_dec.txt");
        let password = "super_secret_password";
        let wrong_password = "wrong_password";
        let original_data = b"Some data to encrypt.";

        fs::write(&in_file, original_data).unwrap();

        AESCrypt::encrypt_file_with_progress(
            in_file.to_str().unwrap(),
            enc_file.to_str().unwrap(),
            password,
            None,
            None,
        ).unwrap();

        let res = AESCrypt::decrypt_file_with_progress(
            enc_file.to_str().unwrap(),
            dec_file.to_str().unwrap(),
            wrong_password,
            None,
            None,
        );

        assert!(res.is_err());

        let _ = fs::remove_file(&in_file);
        let _ = fs::remove_file(&enc_file);
        let _ = fs::remove_file(&dec_file);
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        let in_file = temp_file_path("test_large_in.bin");
        let enc_file = temp_file_path("test_large_enc.bin");
        let dec_file = temp_file_path("test_large_dec.bin");
        let password = "super_secret_password";

        let mut original_data = vec![0u8; 10000];
        for i in 0..original_data.len() {
            original_data[i] = (i % 256) as u8;
        }

        fs::write(&in_file, &original_data).unwrap();

        AESCrypt::encrypt_file_with_progress(in_file.to_str().unwrap(), enc_file.to_str().unwrap(), password, None, None).unwrap();
        AESCrypt::decrypt_file_with_progress(enc_file.to_str().unwrap(), dec_file.to_str().unwrap(), password, None, None).unwrap();

        let decrypted_data = fs::read(&dec_file).unwrap();
        assert_eq!(original_data.len(), decrypted_data.len());
        assert_eq!(original_data, decrypted_data);

        let _ = fs::remove_file(&in_file);
        let _ = fs::remove_file(&enc_file);
        let _ = fs::remove_file(&dec_file);
    }
}
#![allow(dead_code)]

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA3_256,
}

impl HashAlgorithm {
    pub fn from_str(alg_str: &str) -> Self {
        match alg_str {
            "MD5" => HashAlgorithm::MD5,
            "SHA-1" => HashAlgorithm::SHA1,
            "SHA-256" => HashAlgorithm::SHA256,
            "SHA-3-256" => HashAlgorithm::SHA3_256,
            _ => HashAlgorithm::MD5,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            HashAlgorithm::MD5 => "MD5".to_string(),
            HashAlgorithm::SHA1 => "SHA-1".to_string(),
            HashAlgorithm::SHA256 => "SHA-256".to_string(),
            HashAlgorithm::SHA3_256 => "SHA-3-256".to_string(),
        }
    }
}

pub struct HashUtil;

impl HashUtil {
    /// ===================================================================
    /// 轉換位元組陣列為十六進位字串 (等同 C++ bytesToHexString)
    /// ===================================================================
    fn bytes_to_hex_string(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(&mut s, "{:02x}", b).unwrap();
        }
        s
    }

    /// ===================================================================
    /// 從純文字計算雜湊值
    /// ===================================================================
    pub fn compute_hash_from_text(text: &str, algorithm: HashAlgorithm) -> String {
        match algorithm {
            HashAlgorithm::MD5 => Self::bytes_to_hex_string(&Md5::digest(text)),
            HashAlgorithm::SHA1 => Self::bytes_to_hex_string(&Sha1::digest(text)),
            HashAlgorithm::SHA256 => Self::bytes_to_hex_string(&Sha256::digest(text)),
            HashAlgorithm::SHA3_256 => Self::bytes_to_hex_string(&Sha3_256::digest(text)),
        }
    }

    /// ===================================================================
    /// 泛型串流檔案處理核心 (零動態分派效能最佳化)
    /// ===================================================================
    fn process_file_hash<D: Digest, F>(
        mut file: File,
        total_bytes: u64,
        mut progress_callback: Option<F>,
    ) -> String
    where
        F: FnMut(u32),
    {
        let mut hasher = D::new();
        let mut buffer = [0u8; 4096];
        let mut processed_bytes = 0u64;
        let mut last_percent = -1i32;

        loop {
            let count = match file.read(&mut buffer) {
                Ok(c) if c > 0 => c,
                _ => break,
            };

            hasher.update(&buffer[..count]);
            processed_bytes += count as u64;

            if let Some(ref mut cb) = progress_callback {
                if total_bytes > 0 {
                    let percent = ((processed_bytes as f64 / total_bytes as f64) * 100.0) as i32;
                    if percent > last_percent {
                        cb(percent.min(100) as u32);
                        last_percent = percent;
                    }
                }
            }
        }

        if let Some(ref mut cb) = progress_callback {
            cb(100);
        }

        Self::bytes_to_hex_string(&hasher.finalize())
    }

    /// ===================================================================
    /// 從檔案計算雜湊值，並支援進度條回調
    /// ===================================================================
    pub fn compute_hash_from_file<F>(
        file_path: &str,
        algorithm: HashAlgorithm,
        progress_callback: Option<F>,
    ) -> String
    where
        F: FnMut(u32),
    {
        let file = match File::open(file_path) {
            Ok(f) => f,
            Err(_) => return String::new(),
        };

        let total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);

        match algorithm {
            HashAlgorithm::MD5 => Self::process_file_hash::<Md5, F>(file, total_bytes, progress_callback),
            HashAlgorithm::SHA1 => Self::process_file_hash::<Sha1, F>(file, total_bytes, progress_callback),
            HashAlgorithm::SHA256 => Self::process_file_hash::<Sha256, F>(file, total_bytes, progress_callback),
            HashAlgorithm::SHA3_256 => Self::process_file_hash::<Sha3_256, F>(file, total_bytes, progress_callback),
        }
    }

    /// ===================================================================
    /// 比對目標雜湊值與校驗檔 (如 sha256sum 輸出的格式)
    /// 回傳 (是否相符, 從檔案中解析出的有效雜湊字串)
    /// ===================================================================
    pub fn compare_hash_with_file(target_hash: &str, checksum_file_path: &str) -> (bool, String) {
        let mut file = match File::open(checksum_file_path) {
            Ok(f) => f,
            Err(_) => return (false, String::new()),
        };

        // 防止讀取超大檔案導致 OOM (限制最多 10MB)
        if let Ok(metadata) = file.metadata() {
            if metadata.len() > 10 * 1024 * 1024 {
                return (false, String::new());
            }
        }

        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_err() {
            return (false, String::new());
        }

        // 處理 UTF-16LE, UTF-16BE, UTF-8 BOM, 以及標準 UTF-8
        let content = if bytes.starts_with(&[0xFF, 0xFE]) {
            let u16_data: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u16_data)
        } else if bytes.starts_with(&[0xFE, 0xFF]) {
            let u16_data: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u16_data)
        } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            String::from_utf8_lossy(&bytes[3..]).into_owned()
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };

        let target_hash_lower = target_hash.to_lowercase();
        let mut first_parsed = String::new();
        let mut valid_hash_count = 0;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let end_pos = trimmed.find(|c: char| c == ' ' || c == '\t' || c == '*').unwrap_or(trimmed.len());
            let hash_part = &trimmed[..end_pos];
            
            if hash_part.len() == 32 || hash_part.len() == 40 || hash_part.len() == 64 {
                let parsed = hash_part.to_lowercase();
                
                if valid_hash_count == 0 {
                    first_parsed = parsed.clone();
                }
                valid_hash_count += 1;

                if target_hash_lower == parsed {
                    return (true, parsed);
                }
            }
        }
        
        if valid_hash_count == 0 {
            (false, String::new())
        } else if valid_hash_count == 1 {
            (false, first_parsed)
        } else {
            (false, "[Not found in list]".to_string())
        }
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
    fn test_compute_hash_from_text() {
        let text = "hello world";
        
        assert_eq!(
            HashUtil::compute_hash_from_text(text, HashAlgorithm::MD5),
            "5eb63bbbe01eeed093cb22bb8f5acdc3"
        );
        assert_eq!(
            HashUtil::compute_hash_from_text(text, HashAlgorithm::SHA1),
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        );
        assert_eq!(
            HashUtil::compute_hash_from_text(text, HashAlgorithm::SHA256),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(
            HashUtil::compute_hash_from_text(text, HashAlgorithm::SHA3_256),
            "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
        );
    }

    #[test]
    fn test_compute_hash_from_file() {
        let file_path = temp_file_path("test_hash_file.txt");
        fs::write(&file_path, "hello world").unwrap();

        let result = HashUtil::compute_hash_from_file(
            file_path.to_str().unwrap(),
            HashAlgorithm::SHA256,
            None::<fn(u32)>, // 明確指定一個符合 FnMut(u32) 簽名的空型別
        );
        
        assert_eq!(result, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_compare_hash_with_file() {
        let checksum_path = temp_file_path("test_checksum.sha256");
        let target_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        
        // 模擬 sha256sum 輸出的格式
        fs::write(&checksum_path, format!("{} *some_file.txt\n", target_hash)).unwrap();

        let (is_match, parsed) = HashUtil::compare_hash_with_file(target_hash, checksum_path.to_str().unwrap());
        assert!(is_match);
        assert_eq!(parsed, target_hash);
        let _ = fs::remove_file(&checksum_path);
    }
}
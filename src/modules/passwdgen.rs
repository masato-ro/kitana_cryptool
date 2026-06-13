#![allow(dead_code)]

use rand::rngs::OsRng;
use rand::seq::SliceRandom;

pub struct PasswdGen;

impl PasswdGen {
    /// ===================================================================
    /// 🔑 1. 密碼產生器核心
    /// ===================================================================
    pub fn generate_password(
        length: usize,
        use_upper: bool,
        use_lower: bool,
        use_digits: bool,
        use_symbols: bool,
    ) -> String {
        if length == 0 {
            return String::new();
        }

        let mut charset = String::new();
        if use_upper {
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if use_lower {
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
        if use_digits {
            charset.push_str("0123456789");
        }
        if use_symbols {
            charset.push_str("!@#$%^&*()-_=+[]{}|;:,.<>?");
        }

        if charset.is_empty() {
            return String::new();
        }

        let charset_bytes = charset.as_bytes();
        let mut rng = OsRng;
        let mut result = String::with_capacity(length);

        for _ in 0..length {
            // 使用密碼學安全的隨機抽取，避免傳統取餘數造成的模數偏差(Modulo Bias)
            if let Some(&c) = charset_bytes.choose(&mut rng) {
                result.push(c as char);
            }
        }

        result
    }

    /// ===================================================================
    /// 🛡️ 2. 密碼強度評分機制
    /// ===================================================================
    pub fn get_password_strength_score_simple(password: &str) -> i32 {
        let len = password.len();
        if len < 8 {
            return 0; // Very Weak，長度不足 8
        }

        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_symbol = false;

        for c in password.chars() {
            if c.is_ascii_lowercase() {
                has_lower = true;
            } else if c.is_ascii_uppercase() {
                has_upper = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            } else {
                has_symbol = true;
            }
        }

        let categories = (has_lower as i32)
            + (has_upper as i32)
            + (has_digit as i32)
            + (has_symbol as i32);

        // 重新設計的密碼評分邏輯 (最高 4 分)
        let mut score = 0;

        // 1. 基本長度分數
        if len >= 16 {
            score += 3;
        } else if len >= 12 {
            score += 2;
        } else if len >= 8 {
            score += 1;
        }

        // 2. 多樣性加成
        if categories == 4 {
            score += 2;
        } else if categories == 3 {
            score += 1;
        }

        // 3. 致命扣分規則 (防禦性檢測)
        if categories == 1 {
            score = score.min(1); // 如果只有單一字元類型，頂多只能得 1 分 (Weak)
        }

        // 確保分數在 0 到 4 之間
        score.clamp(0, 4)
    }
}
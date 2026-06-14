# Kitana Cryptool

[English](README.md) | [繁體中文](README_zh.md)

Kitana Cryptool 是一款基於 Rust 和 FLTK 構建的多功能密碼學工具應用程式。它提供了一個直覺的圖形使用者介面（GUI），用於執行各種密碼學操作，包括檔案加密、雜湊值計算、RSA 金鑰產生以及安全密碼產生。

## 功能特性

*   **AES 加密 (AES Crypt)**：使用 AES-256-CBC 和 PBKDF2 金鑰衍生技術安全地加密和解密檔案。支援檔案串流處理，能高效處理大檔案而不會耗盡記憶體。
*   **RSA 加密 (RSA Crypt)**：支援任意長度文字與檔案的混合加密/解密（AES-256 + RSA），透過串流與分塊技術突破傳統 RSA 的長度限制。支援產生與驗證數位簽章（Sign/Verify）以確保資料的真實性與完整性。整合了拖曳和檔案瀏覽功能，實現無縫的檔案工作流程。
*   **RSA 金鑰產生器 (RSA Key Generator)**：產生 RSA 金鑰對（1024、2048、4096 位元），並可匯出為標準 PEM 格式以及 OpenSSH 公鑰格式。
*   **雜湊值工具 (Hash Utility)**：計算純文字與檔案的 MD5、SHA-1、SHA-256 和 SHA3-256 雜湊值。可透過將計算出的雜湊值與現有的校驗檔進行比對，輕鬆驗證檔案完整性。
*   **密碼產生器 (Password Generator)**：產生高度隨機的安全密碼，支援自訂長度及字元集（大寫字母、小寫字母、數字、符號），並配有直覺的密碼強度指示器。
*   **跨平台 GUI**：由 FLTK 框架驅動，提供輕量、快速且具備原生感的介面。

## 前提條件

請確保您的系統上已安裝 [Rust](https://www.rust-lang.org/tools/install)。
根據您的作業系統，您可能還需要安裝 CMake 和 C/C++ 編譯器，以便 `fltk-rs` 套件（crate）能正確編譯。

## 建置與執行

1.  複製儲存庫：
    ```bash
    git clone https://github.com/yourusername/kitana_cryptool.git
    cd kitana_cryptool
    ```

2.  建置專案：
    ```bash
    cargo build --release
    ```

3.  執行應用程式：
    ```bash
    cargo run --release
    ```

## 致謝

本專案使用了以下開源函式庫：
*   fltk-rs (MIT/LGPL)
*   RustCrypto (`aes`, `cbc`, `cipher`, `md-5`, `pbkdf2`, `rsa`, `sha1`, `sha2`, `sha3`, `signature`) (MIT/Apache 2.0)
*   rand、`getrandom` 與 `base64` (MIT/Apache 2.0)
*   winres (MIT)

## 授權條款

本軟體採用 MIT 授權條款。詳情請參閱 `LICENSE` 檔案。

# Kitana Cryptool

[English](README.md) | [繁體中文](README_zh.md)

Kitana Cryptool is a versatile cryptographic utility application built with Rust and FLTK. It provides a user-friendly graphical interface (GUI) for performing various cryptographic operations including file encryption, hash calculation, RSA key generation, and secure password generation.

## Features

*   **AES Crypt**: Securely encrypt and decrypt files using AES-256-CBC with PBKDF2 key derivation. Features file streaming to handle large files efficiently without exhausting memory.
*   **RSA Crypt**: Hybrid encryption (AES-256 + RSA) for both texts and files of any size, overcoming traditional RSA size limits through streaming/chunking. Supports generating and verifying digital signatures (Sign/Verify) for both texts and files to ensure data authenticity and integrity. Integrates drag-and-drop or file browsing for seamless file-based workflows.
*   **RSA Key Generator**: Generate RSA key pairs (1024, 2048, 4096 bits) and export them in standard PEM formats as well as the OpenSSH public key format.
*   **Hash Utility**: Calculate MD5, SHA-1, SHA-256, and SHA3-256 hashes for plain texts and files. Easily verify file integrity by comparing computed hashes against existing checksum files.
*   **Password Generator**: Generate highly secure random passwords with customizable length and character sets (uppercase, lowercase, digits, symbols), complete with a visual password strength indicator.
*   **Cross-platform GUI**: Powered by the FLTK framework for a lightweight, fast, and native-feeling interface.

## Prerequisites

Ensure you have [Rust](https://www.rust-lang.org/tools/install) installed on your system. 
Depending on your operating system, you might also need to install CMake and a C/C++ compiler for the `fltk-rs` crate to build correctly.

## Building and Running

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/kitana_cryptool.git
    cd kitana_cryptool
    ```

2.  Build the project:
    ```bash
    cargo build --release
    ```

3.  Run the application:
    ```bash
    cargo run --release
    ```

## Acknowledgements

This project uses the following open-source libraries:
*   fltk-rs (MIT/LGPL)
*   RustCrypto (`aes`, `cbc`, `cipher`, `md-5`, `pbkdf2`, `rsa`, `sha1`, `sha2`, `sha3`, `signature`) (MIT/Apache 2.0)
*   rand, `getrandom` & `base64` (MIT/Apache 2.0)
*   sys-locale (MIT/Apache 2.0)
*   winres (MIT)

## License

This software is licensed under the MIT License. See the `LICENSE` file for more details.
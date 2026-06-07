# Kitana Cryptool

A simple, cross-platform cryptographic utility built with C++, FLTK, and OpenSSL.

![Screenshot](screenshot.png)  <!-- 預留給您的應用程式截圖 -->

## Features

*   **AES Encryption/Decryption**: Encrypt and decrypt files using AES-256-CBC with a password-derived key (PBKDF2).
*   **RSA Key Generation**: Generate RSA key pairs (1024, 2048, 4096 bits) and export public keys in OpenSSH format.
*   **Password Generator**: Create strong, random passwords with customizable character sets (uppercase, lowercase, digits, symbols) and length.
*   **Hash Calculation**: Compute MD5, SHA-1, SHA-256, and SHA-3-256 hashes for both text and files, with progress indication for large files.
*   **Hash Comparison**: Verify file integrity by comparing a computed hash against a checksum file.
*   **Cross-Platform**: Designed to be compiled and run on both Windows (MSVC/MinGW) and Linux.

## Building from Source

### Prerequisites

*   A C++20 compatible compiler (MSVC, GCC, Clang)
*   CMake (version 3.20 or higher)
*   OpenSSL (v3.x recommended)

### Windows (with MSVC and vcpkg)

1.  **Install OpenSSL via vcpkg**:
    ```bash
    vcpkg install openssl:x64-windows
    ```

2.  **Configure with CMake**:
    Point CMake to the vcpkg toolchain file.
    ```bash
    cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[path-to-vcpkg]/scripts/buildsystems/vcpkg.cmake
    ```

3.  **Build**:
    ```bash
    cmake --build build --config Release
    ```
    The executable will be in `build/Release/`.

### Linux (Debian/Ubuntu)

1.  **Install Dependencies**:
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential cmake libfltk1.3-dev libssl-dev
    ```

2.  **Configure and Build**:
    ```bash
    cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ```
    The executable will be in `build/`.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
The project utilizes third-party libraries with their own licenses:
*   **FLTK**: LGPL-2.0 with exceptions
*   **OpenSSL**: Apache License 2.0

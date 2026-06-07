# Kitana Cryptool

A simple, cross-platform cryptographic utility built with C++, FLTK, and OpenSSL.

![Screenshot](src/app.png)

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

### Windows (MSVC / vcpkg)

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

### Windows (MinGW / MSYS2)

1.  **Install Dependencies via MSYS2**:
    Open the MSYS2 UCRT64 terminal and install the required packages:
    ```bash
    pacman -S mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-openssl
    ```

2.  **Configure and Build**:
    ```bash
    cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ```
    The executable will be in `build/`.

### Linux (Debian/Ubuntu)

1.  **Install Dependencies**:
    Since this project uses `FetchContent` to build FLTK 1.4 from source, you only need to install the underlying dependencies for the X11 windowing system and OpenGL.
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential cmake libx11-dev libxext-dev libxft-dev libxinerama-dev libxcursor-dev libxrender-dev libxfixes-dev libgl1-mesa-dev libglu1-mesa-dev libssl-dev
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
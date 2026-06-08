# Kitana Cryptool

A high-performance, ultra-lightweight, cross-platform cryptographic desktop utility built with pure C++20, FLTK (1.4), and OpenSSL (3.x). 

Designed with a "zero-dependency single-executable" philosophy for Windows and a "fully self-contained standalone sandbox app" architecture for macOS.

![Screenshot](src/app.png)

## Features

* **Military-Grade Symmetric Encryption**: Encrypt and decrypt files of any size using **AES-256-CBC**. Features randomized per-file Salts combined with a hardened key derivation function (**PBKDF2-HMAC-SHA256**) to fully neutralize GPU dictionary and rainbow-table attacks. Includes tailored protection against padding oracle side-channel analysis.
* **Next-Gen Asymmetric Cryptography (Coming Soon)**: Transitioning beyond legacy RSA to modern **ECC (Elliptic Curve Cryptography)** leveraging high-speed `Ed25519` / `X25519` curves for agile, bulletproof public-key hybrid encryption and digital signatures.
* **Cryptographic Password Generator**: Generate cryptographically secure random passwords driven directly by OS hardware entropy pools, with customized lengths and character sets (Uppercase, Lowercase, Digits, Symbols).
* **Multi-Engine Hash Calculation**: Compute real-time MD5, SHA-1, SHA-256, and SHA-3-256 checksums for text or multi-gigabyte files, equipped with a smooth, low-overhead progress callback engine.
* **Integrity Verification Engine**: Verify file tamper-resistance by performing binary hash comparisons against independent checksum indices.
* **Elite UI Fluidity**: Powered by FLTK's retained-mode standard C++ callback loops. Tailored with context-native menu handling (bypassing generic OS overrides) and native read-only fields that retain beautiful, uncompromised contrast themes.

---

## Building from Source

### Prerequisites

* A C++20 compatible compiler (MSVC 2022+, GCC 11+, or Clang 13+)
* CMake (version 3.20 or higher)
* OpenSSL (v3.x required for modern API compatibility)

---

### 🍏 macOS (Pure Apple Silicon & Intel)

The macOS build pipeline is armed with an automated `POST_BUILD` deployment matrix. It physically extracts OpenSSL binaries from the host system, bundles them using `@executable_path` linkage maps, injects polished `Info.plist` manifests (for beautiful space-separated naming in Activity Monitor and Dock), and seals the sandbox with local Ad-hoc digital signing to eliminate native kernel crashes!

1.  **Install OpenSSL v3 via Homebrew**:
    ```bash
    brew install openssl@3
    ```

2.  **Configure and Compile**:
    ```bash
    cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ```

3.  **Run the Standalone Bundle**:
    The fully localized, self-contained **`Kitana_Cryptool.app`** will be generated inside the `build/` directory. You can compress it into a `.zip` and ship it to any Mac running macOS 11+ without installing any external dependencies!

---

### 💻 Windows (MSVC / vcpkg)

The Windows pipeline incorporates a localized `resource.rc` subsystem compilation. It physically infuses the application icon and embeds the raw PNG assets as binary `RCDATA` directly inside the executable's core memory grid, delivering a completely clean, standalone "Green Single EXE".

1.  **Install OpenSSL via vcpkg**:
    ```bash
    vcpkg install openssl:x64-windows
    ```

2.  **Configure with CMake**:
    ```bash
    cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[path-to-vcpkg]/scripts/buildsystems/vcpkg.cmake
    ```

3.  **Build**:
    ```bash
    cmake --build build --config Release
    ```
    Your clean, single binary executable will reside in `build/Release/Kitana_Cryptool.exe`.

---

### 💻 Windows (MinGW / MSYS2)

For developers using the open UCRT64 GNU toolchain environment:

1.  **Install Packages via MSYS2 Terminal**:
    ```bash
    pacman -S mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-openssl
    ```

2.  **Configure and Build**:
    ```bash
    cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ```

---

### 🐧 Linux (Debian / Ubuntu)

FLTK 1.4 is acquired automatically from upstream source structures via CMake `FetchContent`, meaning only local X11 and OpenGL development headers are required on the host platform.

1.  **Install System Dependencies**:
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential cmake libx11-dev libxext-dev libxft-dev libxinerama-dev libxcursor-dev libxrender-dev libxfixes-dev libgl1-mesa-dev libglu1-mesa-dev libssl-dev
    ```

2.  **Configure and Build**:
    ```bash
    cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ```

---

## 📜 Open Source Licensing Matrix

This project is officially published under the **MIT License**. See the [LICENSE](LICENSE) file for comprehensive legal parameters. 

To honor architectural integrity and upstream compliance, all dynamic asset assets and legal text strings for utilized third-party libraries are embedded in runtime dialog matrices:

* **Kitana Cryptool Core Code**: MIT License (Permissive commercial use and waiver rights)
* **OpenSSL (Crypto Engine)**: Apache License 2.0 (With state-of-the-art software patent defense shields)
* **FLTK (UI Windowing Framework)**: LGPL-2.0 with static-linking exceptions (Fully compliant with closed-source commercial standalone derivation)
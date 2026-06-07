#include "aescrypt.h"

#include <fstream>
#include <vector>
#include <algorithm>
#include <iostream>
#include <filesystem>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

bool AESCrypt::encryptFile(const std::string &inFile, const std::string &outFile, const std::string &password) {
    return encryptFile(inFile, outFile, password, nullptr);
}

bool AESCrypt::decryptFile(const std::string &inFile, const std::string &outFile, const std::string &password) {
    return decryptFile(inFile, outFile, password, nullptr);
}

bool AESCrypt::encryptFile(const std::string &inFile, const std::string &outFile, const std::string &password,
                           const std::function<void(int)> &progressCallback) {
    return cryptFile(inFile, outFile, password, true, progressCallback);
}

bool AESCrypt::decryptFile(const std::string &inFile, const std::string &outFile, const std::string &password,
                           const std::function<void(int)>& progressCallback) {
    return cryptFile(inFile, outFile, password, false, progressCallback);
}

bool AESCrypt::cryptFile(const std::string &inFile, const std::string &outFile, const std::string &password, 
                         bool encrypt, const std::function<void(int)>& progressCallback)
{
    // 🧱 1. 使用 C++ 標準檔案串流直球對決
    std::ifstream in(inFile, std::ios::binary);
    std::ofstream out(outFile, std::ios::binary);

    if (!in.is_open()) {
        std::cerr << "Cannot open input file: " << inFile << std::endl << std::flush;
        return false;
    }
    if (!out.is_open()) {
        std::cerr << "Cannot open output file: " << outFile << std::endl << std::flush;
        return false;
    }

    // 🧱 2. 初始化 OpenSSL 上下文晶片
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_CIPHER_CTX." << std::endl << std::flush;
        ERR_clear_error();
        return false;
    }

    // 🧱 3. 處理隨機鹽值 (Salt)
    unsigned char salt[SALT_LEN];
    if (encrypt) {
        if (RAND_bytes(salt, SALT_LEN) != 1) {
            std::cerr << "Failed to generate salt." << std::endl << std::flush;
            EVP_CIPHER_CTX_free(ctx);
            ERR_clear_error();
            return false;
        }
        out.write(reinterpret_cast<char *>(salt), SALT_LEN);
    } else {
        in.read(reinterpret_cast<char *>(salt), SALT_LEN);
        if (in.gcount() != SALT_LEN) {
            std::cerr << "Failed to read salt from input." << std::endl << std::flush;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // 🧱 4. 派生密鑰與 IV (PBKDF2 核心不變)
    unsigned char key[KEY_LEN], iv[IV_LEN];
    unsigned char keyiv[KEY_LEN + IV_LEN];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                          salt, SALT_LEN,
                          PBKDF2_ITER,
                          EVP_sha256(),
                          KEY_LEN + IV_LEN,
                          keyiv) != 1) {
        std::cerr << "PBKDF2 key derivation failed." << std::endl << std::flush;
        EVP_CIPHER_CTX_free(ctx);
        ERR_clear_error();
        return false;
    }

    std::memcpy(key, keyiv, KEY_LEN);
    std::memcpy(iv, keyiv + KEY_LEN, IV_LEN);

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    if (encrypt) {
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) {
            std::cerr << "EVP_EncryptInit_ex failed." << std::endl << std::flush;
            EVP_CIPHER_CTX_free(ctx);
            ERR_clear_error();
            return false;
        }
    } else {
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) {
            std::cerr << "EVP_DecryptInit_ex failed." << std::endl << std::flush;
            EVP_CIPHER_CTX_free(ctx);
            ERR_clear_error();
            return false;
        }
    }

    // 🧱 5. 緩衝區去 Qt 化：使用標準 std::vector 完美的零依賴配置
    std::vector<char> inBuf(4096);
    std::vector<char> outBuf(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    // 🧱 6. 利用 std::filesystem 獲取檔案總大小 (進度條必備)
    std::error_code ec;
    uint64_t totalBytes = std::filesystem::file_size(inFile, ec);
    if (ec) totalBytes = 0; 
    uint64_t processedBytes = 0;

    // 🧱 7. 檔案加解密主循環
    while (in.read(inBuf.data(), static_cast<std::streamsize>(inBuf.size())) || in.gcount() > 0) {
        std::streamsize bytesRead = in.gcount();

        int ret = 0;
        if (encrypt) {
            ret = EVP_EncryptUpdate(ctx,
                reinterpret_cast<unsigned char*>(outBuf.data()), &outLen,
                reinterpret_cast<const unsigned char*>(inBuf.data()), static_cast<int>(bytesRead));
        } else {
            ret = EVP_DecryptUpdate(ctx,
                reinterpret_cast<unsigned char*>(outBuf.data()), &outLen,
                reinterpret_cast<const unsigned char*>(inBuf.data()), static_cast<int>(bytesRead));
        }

        if (ret != 1) {
            std::cerr << "EVP_EncryptUpdate / EVP_DecryptUpdate failed." << std::endl << std::flush;
            EVP_CIPHER_CTX_free(ctx);
            ERR_clear_error();
            return false;
        }

        out.write(outBuf.data(), outLen);
        
        processedBytes += bytesRead;
        if (progressCallback && totalBytes > 0) {
            int percent = static_cast<int>((processedBytes * 100) / totalBytes);
            progressCallback(std::min(percent, 100));
        }
    }

    // 🧱 8. 結尾 Padding 處理
    int finalLen = 0;
    if (encrypt) {
        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outBuf.data()), &finalLen) != 1) {
            std::cerr << "EVP_EncryptFinal_ex failed." << std::endl << std::flush;
            EVP_CIPHER_CTX_free(ctx);
            ERR_clear_error();
            return false;
        }
    } else {
        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outBuf.data()), &finalLen) != 1) {
            std::cerr << "EVP_DecryptFinal_ex failed. Incorrect password or corrupted file." << std::endl << std::flush;
            EVP_CIPHER_CTX_free(ctx);
            ERR_clear_error(); // 🎯 清理錯誤佇列，避免訊息洩漏到下一個測試
            return false;
        }
    }
    out.write(outBuf.data(), finalLen);

    if (progressCallback) progressCallback(100);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
#include "keygen.h"
#include <fstream>
#include <vector>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

// ===================================================================
// 🛠️ 【密碼學專用：標準 C++ Base64 轉換補丁】
// ===================================================================
static std::string Base64Encode(const std::vector<unsigned char>& data) {
    BUF_MEM *bufferPtr;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

// ===================================================================
// 🎯 【終極防禦】：手寫純 C++ 萬用大端序轉換晶片 (物理超渡 htonl)
// ===================================================================
static uint32_t PureCppHtonl(uint32_t val) {
    return ((val & 0xFF000000) >> 24) |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x000000FF) << 24);
}

// ===================================================================
// 🔑 1. 金鑰對產生核心 (沿用穩定版本)
// ===================================================================
bool KeyGen::generateRSAKeyPair(int bits, const std::string &privatePath, const std::string &publicPath) {
    if (bits < 1024) return false;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    std::ofstream privateFile(privatePath, std::ios::binary);
    if (!privateFile.is_open()) {
        EVP_PKEY_free(pkey);
        return false;
    }
    BIO *privateBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char *privatePemData = nullptr;
    long privateLen = BIO_get_mem_data(privateBio, &privatePemData);
    privateFile.write(privatePemData, privateLen);
    privateFile.close();
    BIO_free(privateBio);

    std::ofstream publicFile(publicPath, std::ios::binary);
    if (!publicFile.is_open()) {
        EVP_PKEY_free(pkey);
        return false;
    }
    BIO *publicBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicBio, pkey);
    char *publicPemData = nullptr;
    long publicLen = BIO_get_mem_data(publicBio, &publicPemData);
    publicFile.write(publicPemData, publicLen);
    publicFile.close();
    BIO_free(publicBio);

    EVP_PKEY_free(pkey);
    return true;
}

// ===================================================================
// 🔑 2. 從檔案載入私鑰指標 (沿用穩定版本)
// ===================================================================
EVP_PKEY* KeyGen::loadPrivateKeyFromFile(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return nullptr;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> keyData(size);
    if (!file.read(keyData.data(), size)) return nullptr;
    file.close();

    BIO *bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
    if (!bio) return nullptr;

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

// ===================================================================
// 🔑 3. 【OpenSSL 3.x 現代化 API】的純 C++ OpenSSH 公鑰生成函式
// ===================================================================
std::string KeyGen::generateOpenSSHPublicKey(const EVP_PKEY *pkey, const std::string &comment) {
    if (!pkey) return "";

    BIGNUM *n = nullptr;
    BIGNUM *e = nullptr;

    if (EVP_PKEY_get_bn_param(pkey, "n", &n) <= 0 || n == nullptr) {
        std::cerr << "Failed to get RSA modulus 'n'." << std::endl;
        return "";
    }
    if (EVP_PKEY_get_bn_param(pkey, "e", &e) <= 0 || e == nullptr) {
        std::cerr << "Failed to get RSA exponent 'e'." << std::endl;
        BN_free(n);
        return "";
    }

    auto encode_mpint = [](const BIGNUM *bn) -> std::vector<unsigned char> {
        int len = BN_num_bytes(bn);
        std::vector<unsigned char> raw(len, 0);
        BN_bn2bin(bn, raw.data());

        if (!raw.empty() && (raw[0] & 0x80)) {
            raw.insert(raw.begin(), 0x00);
        }

        uint32_t net_len = PureCppHtonl(static_cast<uint32_t>(raw.size()));
        std::vector<unsigned char> result;
        result.insert(result.end(), reinterpret_cast<const unsigned char*>(&net_len), reinterpret_cast<const unsigned char*>(&net_len) + 4);
        result.insert(result.end(), raw.begin(), raw.end());
        return result;
    };

    auto encode_string = [](const std::string &str) -> std::vector<unsigned char> {
        uint32_t net_len = PureCppHtonl(static_cast<uint32_t>(str.size()));
        std::vector<unsigned char> result;
        result.insert(result.end(), reinterpret_cast<const unsigned char*>(&net_len), reinterpret_cast<const unsigned char*>(&net_len) + 4);
        result.insert(result.end(), str.begin(), str.end());
        return result;
    };

    std::string type = "ssh-rsa";
    std::vector<unsigned char> blob;

    auto t_blob = encode_string(type);
    blob.insert(blob.end(), t_blob.begin(), t_blob.end());

    auto e_blob = encode_mpint(e);
    blob.insert(blob.end(), e_blob.begin(), e_blob.end());

    auto n_blob = encode_mpint(n);
    blob.insert(blob.end(), n_blob.begin(), n_blob.end());

    std::string base64 = Base64Encode(blob);
    std::string finalKey = "ssh-rsa " + base64;
    if (!comment.empty()) {
        finalKey += " " + comment;
    }

    BN_free(n);
    BN_free(e);
    return finalKey;
}
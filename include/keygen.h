#ifndef KEYGEN_H
#define KEYGEN_H

#include <string>
#include <openssl/evp.h>

class KeyGen {
public:
    // 🎯 1. 金鑰對產生核心 (1024/2048/4096 位元)
    static bool generateRSAKeyPair(int bits, const std::string &privPath, const std::string &pubPath);

    // 🎯 2. 從檔案載入私鑰指標 (供 OpenSSH 轉檔使用)
    static EVP_PKEY* loadPrivateKeyFromFile(const std::string &filePath);

    // 🎯 3. 純 C++ 物理生成 OpenSSH 公鑰格式字串 (ssh-rsa BASE64_BLOB comment)
    static std::string generateOpenSSHPublicKey(const EVP_PKEY *pkey, const std::string &comment);
};

#endif // KEYGEN_H
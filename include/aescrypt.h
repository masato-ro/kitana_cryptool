#ifndef AESCRYPT_H
#define AESCRYPT_H

#include <string>
#include <functional>

class AESCrypt
{
public:
    AESCrypt() = default;

    static bool encryptFile(const std::string &inFile, const std::string &outFile, const std::string &password);
    static bool decryptFile(const std::string &inFile, const std::string &outFile, const std::string &password);

    static bool encryptFile(const std::string &inFile, const std::string &outFile, const std::string &password,
                            const std::function<void(int)> &progressCallback);
    static bool decryptFile(const std::string &inFile, const std::string &outFile, const std::string &password,
                            const std::function<void(int)> &progressCallback);

private:
    static bool cryptFile(const std::string &inFile, const std::string &outFile, const std::string &password,
                          bool encrypt, const std::function<void(int)> &progressCallback);

    static constexpr int KEY_LEN = 32;   // AES-256
    static constexpr int IV_LEN = 16;    // AES block size
    static constexpr int SALT_LEN = 8;
    static constexpr int PBKDF2_ITER = 100000; // 死死鎖定 10 萬次黃金防線
};

#endif // AESCRYPT_H
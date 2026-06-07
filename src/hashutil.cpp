#include "hashutil.h"
#include <openssl/evp.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <cctype>

HashAlgorithm toHashAlgorithm(const std::string &algStr) {
    if (algStr == "MD5") return HashAlgorithm::MD5;
    if (algStr == "SHA-1") return HashAlgorithm::SHA1;
    if (algStr == "SHA-256") return HashAlgorithm::SHA256;
    if (algStr == "SHA-3-256") return HashAlgorithm::SHA3_256;
    return HashAlgorithm::MD5;
}

std::string hashAlgorithmToString(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5: return "MD5";
        case HashAlgorithm::SHA1: return "SHA-1";
        case HashAlgorithm::SHA256: return "SHA-256";
        case HashAlgorithm::SHA3_256: return "SHA-3-256";
    }
    return "MD5";
}

namespace HashUtil {

// 根據我們的演算法列舉，取得對應的 OpenSSL EVP_MD 物件
const EVP_MD* getEvpMd(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5:       return EVP_md5();
        case HashAlgorithm::SHA1:      return EVP_sha1();
        case HashAlgorithm::SHA256:    return EVP_sha256();
        case HashAlgorithm::SHA3_256:  return EVP_sha3_256();
    }
    return EVP_md5(); // 預設
}

// 將二進位的 hash 結果轉換為十六進位字串
std::string bytesToHexString(const unsigned char* bytes, unsigned int len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::string computeHashFromText(const std::string &text, HashAlgorithm algorithm) {
    const EVP_MD* md = getEvpMd(algorithm);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, text.c_str(), text.length());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    return bytesToHexString(md_value, md_len);
}

std::string computeHashFromFile(const std::string &filePath, HashAlgorithm algorithm,
                                const std::function<void(int)>& progressCallback)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    const EVP_MD* md = getEvpMd(algorithm);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestInit_ex(mdctx, md, nullptr);

    const uint64_t totalBytes = std::filesystem::file_size(filePath);
    uint64_t processedBytes = 0;
    constexpr size_t bufferSize = 4096;
    std::vector<char> buffer(bufferSize);

    int lastPercent = -1;

    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        EVP_DigestUpdate(mdctx, buffer.data(), file.gcount());
        processedBytes += file.gcount();

        if (progressCallback && totalBytes > 0) {
            int percent = static_cast<int>((processedBytes * 100) / totalBytes);

            if (percent > lastPercent) {
                progressCallback(std::min(percent, 100));
                lastPercent = percent;
            }
        }
    }

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    if (progressCallback) {
        progressCallback(100);
    }

    return bytesToHexString(md_value, md_len);
}

bool compareHashWithFile(const std::string &targetHash, const std::string &checksumFilePath, std::string &parsedHashFromFile) {
    parsedHashFromFile = "";
    std::ifstream checkFile(checksumFilePath);
    if (!checkFile.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(checkFile, line)) {
        // Trim leading/trailing whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) continue;

        size_t endPos = line.find_first_of(" \t*");
        if (endPos != std::string::npos) {
            line = line.substr(0, endPos);
        }

        std::ranges::transform(line, line.begin(),
                               [](unsigned char c){ return std::tolower(c); });

        if (line.length() == 32 || line.length() == 40 || line.length() == 64) {
            parsedHashFromFile = line;
            break;
        }
    }
    checkFile.close();

    if (parsedHashFromFile.empty()) {
        return false;
    }

    std::string lowerTargetHash = targetHash;
    std::ranges::transform(lowerTargetHash, lowerTargetHash.begin(),
                           [](unsigned char c){ return std::tolower(c); });

    return lowerTargetHash == parsedHashFromFile;
}

} // namespace HashUtil
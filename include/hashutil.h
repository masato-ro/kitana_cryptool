#ifndef HASHUTIL_H
#define HASHUTIL_H

#include <string>
#include <functional>

// 定義支援的雜湊演算法
enum class HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA3_256
};

// 工具函式，用於演算法與字串之間的轉換
HashAlgorithm toHashAlgorithm(const std::string &algStr);
std::string hashAlgorithmToString(HashAlgorithm algorithm);

namespace HashUtil {

/**
 * @brief 從文字計算雜湊值。
 * @param text 輸入的文字。
 * @param algorithm 使用的雜湊演算法。
 * @return 計算出的十六進位雜湊值字串。
 */
std::string computeHashFromText(const std::string &text, HashAlgorithm algorithm);

/**
 * @brief 從檔案計算雜湊值。
 * @param filePath 檔案路徑。
 * @param algorithm 使用的雜湊演算法。
 * @param progressCallback 進度回呼函式 (0-100)。
 * @return 計算出的十六進位雜湊值字串；如果檔案開啟失敗則返回空字串。
 */
std::string computeHashFromFile(const std::string &filePath, HashAlgorithm algorithm,
                                const std::function<void(int)>& progressCallback);

/**
 * @brief 解析 Checksum 檔案，並與提供的 Hash 值進行安全比對
 *
 * @param targetHash 您已經計算出來的正確 Hash 值 (將被轉換為小寫比對)
 * @param checksumFilePath 使用者提供的 Checksum 檔案路徑 (.sha256, .md5 等)
 * @param parsedHashFromFile [輸出] 成功從檔案中解析出的 Hash 字串 (如果解析失敗則為空)
 * @return bool 如果兩者完全一致回傳 true，否則回傳 false
 */
bool compareHashWithFile(const std::string &targetHash, const std::string &checksumFilePath, std::string &parsedHashFromFile);

} // namespace HashUtil

#endif // HASHUTIL_H
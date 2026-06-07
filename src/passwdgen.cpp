#include "passwdgen.h"
#include <openssl/rand.h>
#include <cctype>
#include <algorithm> // 引入 std::min

namespace PasswdGen {

std::string generatePassword(int length, bool useUpper, bool useLower, bool useDigits, bool useSymbols) {
    const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    const std::string digits = "0123456789";
    const std::string symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    std::string charset;
    if (useUpper) charset += upper;
    if (useLower) charset += lower;
    if (useDigits) charset += digits;
    if (useSymbols) charset += symbols;

    if (charset.empty() || length <= 0) return "";

    std::string result;
    result.reserve(length);

    for (int i = 0; i < length; ++i) {
        unsigned char byte;
        if (RAND_bytes(&byte, 1) != 1) return ""; // OpenSSL fail
        // 修正隱式型別轉換警告
        int index = static_cast<int>(byte % charset.length());
        result.push_back(charset[index]);
    }

    return result;
}

int getPasswordStrengthScoreSimple(const std::string& password) {
    if (password.length() < 8) {
        return 0; // Very Weak，長度不足8
    }

    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSymbol = false;

    for (char c : password) {
        if (std::islower(static_cast<unsigned char>(c))) {
            hasLower = true;
        } else if (std::isupper(static_cast<unsigned char>(c))) {
            hasUpper = true;
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            hasDigit = true;
        } else {
            hasSymbol = true;
        }
    }

    int categories = hasLower + hasUpper + hasDigit + hasSymbol;

    // 重新設計的密碼評分邏輯 (最高 4 分)
    int score = 0;
    int len = static_cast<int>(password.length());

    // 1. 基本長度分數
    if (len >= 8 && len < 12) score += 1;
    else if (len >= 12 && len < 16) score += 2;
    else if (len >= 16) score += 3;

    // 2. 多樣性加成
    if (categories == 3) score += 1;
    else if (categories == 4) score += 2;

    // 3. 致命扣分規則 (防禦性檢測)
    // 如果只有一種字元類型 (例如只有數字，或只有小寫)，即使很長也不安全
    if (categories == 1) {
        score = std::min(score, 1); // 頂多只能得 1 分 (Weak)
    }

    // 確保分數在 0 到 4 之間
    if (score < 0) score = 0;
    if (score > 4) score = 4;

    return score;
}

} // namespace PasswdGen
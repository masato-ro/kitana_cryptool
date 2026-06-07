#ifndef PASSWDGEN_H
#define PASSWDGEN_H

#include <string>

namespace PasswdGen {

/**
 * @brief 產生一個隨機密碼字串。
 *
 * @param length 期望的密碼長度。
 * @param useUpper 是否包含大寫字母。
 * @param useLower 是否包含小寫字母。
 * @param useDigits 是否包含數字。
 * @param useSymbols 是否包含特殊符號。
 * @return 產生的隨機密碼；如果字元集為空或 OpenSSL 隨機數產生失敗，則返回空字串。
 */
std::string generatePassword(int length, bool useUpper, bool useLower, bool useDigits, bool useSymbols);

/**
 * @brief 簡單評估密碼的強度分數。
 *
 * 分數範圍從 0 (非常弱) 到 4 (非常強)。
 * - 長度小於 8: 0分
 * - 分數計算: (長度 / 4) + (字元種類數 * 2)，上限為 4。
 *
 * @param password 要評估的密碼。
 * @return 密碼強度分數 (0-4)。
 */
int getPasswordStrengthScoreSimple(const std::string& password);

} // namespace PasswdGen

#endif // PASSWDGEN_H
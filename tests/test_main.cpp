#include <gtest/gtest.h>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/provider.h>

#include "aescrypt.h"
#include "keygen.h"
#include "passwdgen.h"
#include "hashutil.h"

// Helper function: Read file content into a string
std::string ReadFileToString(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    return std::string{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

// Test fixture for automatic file cleanup before and after each test
class CryptoTest : public ::testing::Test {
protected:
    void TearDown() override {
        // Delete all possible test files after each test case
        std::filesystem::remove("test_original.txt");
        std::filesystem::remove("test_encrypted.bin");
        std::filesystem::remove("test_decrypted.txt");
        std::filesystem::remove("decrypted_fail.txt");
        std::filesystem::remove("test_id_rsa");
        std::filesystem::remove("test_id_rsa.pub");
        std::filesystem::remove("test_ssh_id_rsa");
        std::filesystem::remove("test_ssh_id_rsa.pub");
        std::filesystem::remove("test_hash.txt");
        std::filesystem::remove("test_checksum.sha256");
        std::filesystem::remove("test_checksum_invalid.txt");
    }
};

// Test Case 1: AES Encryption and Decryption process
TEST_F(CryptoTest, AESCryptDecrypt) {
    const std::string original_content = "This is a top secret message for testing purposes.";
    const std::string password = "strong_password_123";
    const std::string wrong_password = "wrong_password";
    const std::string original_file = "test_original.txt";
    const std::string encrypted_file = "test_encrypted.bin";
    const std::string decrypted_file = "test_decrypted.txt";

    std::ofstream(original_file) << original_content;

    // 1. Test encryption
    ASSERT_TRUE(AESCrypt::encryptFile(original_file, encrypted_file, password));

    // 2. Test decryption with correct password
    ASSERT_TRUE(AESCrypt::decryptFile(encrypted_file, decrypted_file, password));

    // 3. Verify content consistency
    const std::string decrypted_content = ReadFileToString(decrypted_file);
    ASSERT_EQ(original_content, decrypted_content);

    // 4. Test decryption with incorrect password (expected to fail)
    std::cout << "[   INFO   ] Testing incorrect password decryption. Expecting an EVP error message below:" << std::endl;
    bool decrypt_result = AESCrypt::decryptFile(encrypted_file, "decrypted_fail.txt", wrong_password);
    ASSERT_FALSE(decrypt_result);
    std::cout << "[   INFO   ] Incorrect password correctly blocked. Test passed." << std::endl;
}

// Test Case 2: RSA Key Pair Generation
TEST_F(CryptoTest, KeyGeneration) {
    const std::string private_key_path = "test_id_rsa";
    const std::string public_key_path = "test_id_rsa.pub";

    // 1. Generate key pair
    ASSERT_TRUE(KeyGen::generateRSAKeyPair(2048, private_key_path, public_key_path));

    // 2. Check if files exist
    ASSERT_TRUE(std::filesystem::exists(private_key_path));
    ASSERT_TRUE(std::filesystem::exists(public_key_path));
}

// Test Case 3: OpenSSH Public Key Format
TEST_F(CryptoTest, OpenSSHFormat) {
    const std::string private_key_path = "test_ssh_id_rsa";
    const std::string public_key_path = "test_ssh_id_rsa.pub";
    const std::string comment = "test@example.com";

    // 1. Generate key pair
    ASSERT_TRUE(KeyGen::generateRSAKeyPair(2048, private_key_path, public_key_path));

    // 2. Load private key and generate OpenSSH format public key
    EVP_PKEY* pkey = KeyGen::loadPrivateKeyFromFile(private_key_path);
    ASSERT_NE(pkey, nullptr);

    std::string ssh_pub_key = KeyGen::generateOpenSSHPublicKey(pkey, comment);
    EVP_PKEY_free(pkey);

    // 3. 驗證格式
    ASSERT_FALSE(ssh_pub_key.empty());
    ASSERT_EQ(ssh_pub_key.rfind("ssh-rsa ", 0), 0);
    ASSERT_NE(ssh_pub_key.find(comment), std::string::npos);

    // Optionally print the key for inspection
    std::cout << "[   INFO   ] Generated SSH Key: " << ssh_pub_key << std::endl;
}

// Test Case 4: Password Generator and Strength Evaluation
TEST_F(CryptoTest, PasswordGenerationAndStrength) {
    // 1. Test if generated password length is correct
    std::string pwd1 = PasswdGen::generatePassword(16, true, true, true, true);
    ASSERT_EQ(pwd1.length(), 16);

    // 2. Test strength evaluation: Very Weak (insufficient length)
    ASSERT_EQ(PasswdGen::getPasswordStrengthScoreSimple("1234567"), 0);

    // 3. Test strength evaluation: Weak (single character type)
    ASSERT_EQ(PasswdGen::getPasswordStrengthScoreSimple("1234567890123456"), 1);
    ASSERT_EQ(PasswdGen::getPasswordStrengthScoreSimple("abcdefghijklmnop"), 1);

    // 4. Test strength evaluation: Strong (high diversity and sufficient length)
    std::string strong_pwd = PasswdGen::generatePassword(16, true, true, true, true);
    ASSERT_GE(PasswdGen::getPasswordStrengthScoreSimple(strong_pwd), 3); // Must be at least Good or Strong

    // 5. Test edge case: No character types selected
    std::string empty_pwd = PasswdGen::generatePassword(16, false, false, false, false);
    ASSERT_TRUE(empty_pwd.empty());
}

// Test Case 5: Hash Computation
TEST_F(CryptoTest, HashComputation) {
    const std::string text = "Hello, Cryptography!";
    const std::string expected_sha256 = "29aff889935f5a275ec562ef46c138e917a270aab79b4d5577ee8ea5af308f73";

    // 1. Test SHA-256 computation from text
    std::string text_hash = HashUtil::computeHashFromText(text, HashAlgorithm::SHA256);
    ASSERT_EQ(text_hash, expected_sha256);

    // 2. Test SHA-256 computation from file
    const std::string hash_file = "test_hash.txt";
    std::ofstream(hash_file) << text;

    std::string file_hash = HashUtil::computeHashFromFile(hash_file, HashAlgorithm::SHA256, nullptr);
    ASSERT_EQ(file_hash, expected_sha256);

    // 3. Ensure text computation and file computation results are consistent
    ASSERT_EQ(text_hash, file_hash);
}

// Test Case 6: Hash Comparison Functionality
TEST_F(CryptoTest, HashComparison) {
    const std::string correct_hash = "29aff889935f5a275ec562ef46c138e917a270aab79b4d5577ee8ea5af308f73";
    const std::string wrong_hash   = "0000000000000000000000000000000000000000000000000000000000000000";
    std::string parsed_hash;

    // 1. Prepare a valid checksum file (standard coreutils format)
    const std::string valid_checksum_file = "test_checksum.sha256";
    std::ofstream(valid_checksum_file) << correct_hash << " *test_hash.txt\n";

    // Test: Correct hash should match successfully
    ASSERT_TRUE(HashUtil::compareHashWithFile(correct_hash, valid_checksum_file, parsed_hash));
    ASSERT_EQ(parsed_hash, correct_hash);

    // Test: Incorrect hash should fail comparison, but still parse the hash from file correctly
    ASSERT_FALSE(HashUtil::compareHashWithFile(wrong_hash, valid_checksum_file, parsed_hash));
    ASSERT_EQ(parsed_hash, correct_hash);

    // 2. Prepare an invalid checksum file (random text)
    const std::string invalid_checksum_file = "test_checksum_invalid.txt";
    std::ofstream(invalid_checksum_file) << "This is not a hash file.\nJust some random text.\n";

    // Test: Invalid file should fail comparison and fail to parse a hash
    parsed_hash.clear();
    ASSERT_FALSE(HashUtil::compareHashWithFile(correct_hash, invalid_checksum_file, parsed_hash));
    ASSERT_TRUE(parsed_hash.empty());

    // 3. Test case-insensitive comparison
    std::string uppercase_correct_hash = "29AFF889935F5A275EC562EF46C138E917A270AAB79B4D5577EE8EA5AF308F73";
    ASSERT_TRUE(HashUtil::compareHashWithFile(uppercase_correct_hash, valid_checksum_file, parsed_hash));
}

int main(int argc, char **argv) {
    // 針對 OpenSSL 3.x，需要手動載入預設的演算法提供者
    OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER_load(nullptr, "base");

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
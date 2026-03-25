#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "encrypt_decrypt.hpp"

// TODO: Check and update tests

namespace {

TEST(PasswordRulesTest, AcceptsLowercasePasswordWithMinimumLength) {
  EXPECT_TRUE(is_valid_password("lowercase"));
}

TEST(PasswordRulesTest, RejectsPasswordThatIsTooShort) {
  EXPECT_FALSE(is_valid_password("short"));
}

TEST(PasswordRulesTest, RejectsPasswordWithUppercaseCharacters) {
  EXPECT_FALSE(is_valid_password("Lowercase"));
}

TEST(PasswordRulesTest, RejectsPasswordWithDigitsOrSymbols) {
  EXPECT_FALSE(is_valid_password("lower123"));
  EXPECT_FALSE(is_valid_password("lowercase!"));
}

TEST(EncryptDecryptTest, EncryptFileDoesNotThrow) {
  EXPECT_NO_THROW(encrypt_file("a_file.txt", "lowercase"));
}

TEST(EncryptDecryptTest, DecryptFileDoesNotThrow) {
  EXPECT_NO_THROW(decrypt_file("a_file.txt.enc", "lowercase"));
}

TEST(EncryptDecryptTest, EncryptCreatesAnOutputFile) {
  const auto input_path = std::filesystem::path("tests_plaintext.txt");
  const auto output_path = std::filesystem::path("tests_plaintext.txt.enc");

  {
    std::ofstream input_file(input_path);
    ASSERT_TRUE(input_file.is_open());
    input_file << "hello security";
  }

  encrypt_file(input_path.string(), "lowercase");

  EXPECT_TRUE(std::filesystem::exists(output_path));

  std::filesystem::remove(input_path);
  std::filesystem::remove(output_path);
}

TEST(EncryptDecryptTest, EncryptThenDecryptShouldRoundTrip) {
  const auto input_path = std::filesystem::path("roundtrip_input.txt");
  const auto encrypted_path = std::filesystem::path("roundtrip_input.txt.enc");
  // TODO: Fix the double extension
  const auto decrypted_path =
      std::filesystem::path("roundtrip_input.txt.enc.dec");

  {
    std::ofstream input_file(input_path);
    ASSERT_TRUE(input_file.is_open());
    input_file << "roundtrip me";
  }

  encrypt_file(input_path.string(), "lowercase");
  decrypt_file(encrypted_path.string(), "lowercase");

  std::ifstream decrypted_file(decrypted_path);
  std::string decrypted_content;
  std::getline(decrypted_file, decrypted_content);

  EXPECT_EQ(decrypted_content, "roundtrip me");

  std::filesystem::remove(input_path);
  std::filesystem::remove(encrypted_path);
  std::filesystem::remove(decrypted_path);
}

}  // namespace

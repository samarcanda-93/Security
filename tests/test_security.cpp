#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "command.hpp"
#include "encrypt_decrypt.hpp"

// TODO: Check and update tests

namespace {

TEST(PasswordRulesTest, AcceptsLowercasePasswordWithMinimumLength) {
  EXPECT_TRUE(is_valid_password("alongsentencepasswordiseasytoremember"));
}

TEST(PasswordRulesTest, RejectsPasswordThatIsTooShort) {
  EXPECT_FALSE(is_valid_password("short"));
}

TEST(PasswordRulesTest, RejectsPasswordWithUppercaseCharacters) {
  EXPECT_FALSE(is_valid_password("IfThePasswordIsLongYouDontNeedUpperCase"));
}

TEST(PasswordRulesTest, RejectsPasswordWithDigitsOrSymbols) {
  EXPECT_FALSE(is_valid_password("ifthepasswordislongyoudontneed123"));
  EXPECT_FALSE(
      is_valid_password("ifthepasswordislongyoudontneedspecialcharachters!"));
}

TEST(EncryptDecryptTest, EncryptFileDoesNotThrow) {
  const auto input_path = std::filesystem::path("encrypt_no_throw.txt");
  const auto output_path = std::filesystem::path("encrypt_no_throw.txt.enc");

  {
    std::ofstream input_file(input_path);
    ASSERT_TRUE(input_file.is_open());
    input_file << "hello security";
  }

  EXPECT_NO_THROW(encrypt_file(Task("encrypt", input_path.string()),
                               "alongsentencepasswordiseasytoremember"));

  std::filesystem::remove(input_path);
  std::filesystem::remove(output_path);
}

TEST(EncryptDecryptTest, DecryptFileDoesNotThrow) {
  const auto input_path = std::filesystem::path("decrypt_no_throw.txt");
  const auto encrypted_path = std::filesystem::path("decrypt_no_throw.txt.enc");
  const auto decrypted_path =
      std::filesystem::path("decrypt_no_throw.txt.enc.dec");

  {
    std::ofstream input_file(input_path);
    ASSERT_TRUE(input_file.is_open());
    input_file << "hello security";
  }

  encrypt_file(Task("encrypt", input_path.string()),
               "alongsentencepasswordiseasytoremember");

  EXPECT_NO_THROW(decrypt_file(Task("decrypt", encrypted_path.string()),
                               "alongsentencepasswordiseasytoremember"));

  std::filesystem::remove(input_path);
  std::filesystem::remove(encrypted_path);
  std::filesystem::remove(decrypted_path);
}

TEST(EncryptDecryptTest, EncryptCreatesAnOutputFile) {
  const auto input_path = std::filesystem::path("tests_plaintext.txt");
  const auto output_path = std::filesystem::path("tests_plaintext.txt.enc");

  {
    std::ofstream input_file(input_path);
    ASSERT_TRUE(input_file.is_open());
    input_file << "hello security";
  }

  encrypt_file(Task("encrypt", input_path.string()),
               "alongsentencepasswordiseasytoremember");

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

  encrypt_file(Task("encrypt", input_path.string()),
               "alongsentencepasswordiseasytoremember");
  decrypt_file(Task("decrypt", encrypted_path.string()),
               "alongsentencepasswordiseasytoremember");

  std::ifstream decrypted_file(decrypted_path);
  std::string decrypted_content;
  std::getline(decrypted_file, decrypted_content);

  EXPECT_EQ(decrypted_content, "roundtrip me");

  std::filesystem::remove(input_path);
  std::filesystem::remove(encrypted_path);
  std::filesystem::remove(decrypted_path);
}

}  // namespace

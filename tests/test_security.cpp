#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "command.hpp"
#include "encrypt_decrypt.hpp"

namespace {

TEST(PasswordRulesTest, AcceptsLowercasePasswordWithMinimumLength) {
  EXPECT_NO_THROW(
      detail::Password("alongsentencepasswordiseasytoremember"));
}

TEST(PasswordRulesTest, RejectsPasswordThatIsTooShort) {
  EXPECT_THROW(detail::Password("short"), std::runtime_error);
}

TEST(PasswordRulesTest, RejectsPasswordWithUppercaseCharacters) {
  EXPECT_THROW(detail::Password("IfThePasswordIsLongYouDontNeedUpperCase"),
               std::runtime_error);
}

TEST(PasswordRulesTest, RejectsPasswordWithDigitsOrSymbols) {
  EXPECT_THROW(detail::Password("ifthepasswordislongyoudontneed123"),
               std::runtime_error);
  EXPECT_THROW(
      detail::Password("ifthepasswordislongyoudontneedspecialcharachters!"),
      std::runtime_error);
}

TEST(EncryptDecryptTest, EncryptFileDoesNotThrow) {
  const auto input_path = std::filesystem::path("encrypt_no_throw.txt");
  const auto output_path = std::filesystem::path("encrypt_no_throw.txt.enc");

  {
    std::ofstream input_file(input_path);
    ASSERT_TRUE(input_file.is_open());
    input_file << "hello security";
  }

  const auto password =
      detail::Password("alongsentencepasswordiseasytoremember");

  EXPECT_NO_THROW(
      detail::encrypt_file(Task("encrypt", input_path.string()), password));

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

  const auto password =
      detail::Password("alongsentencepasswordiseasytoremember");

  detail::encrypt_file(Task("encrypt", input_path.string()), password);

  EXPECT_NO_THROW(
      detail::decrypt_file(Task("decrypt", encrypted_path.string()), password));

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

  const auto password =
      detail::Password("alongsentencepasswordiseasytoremember");

  detail::encrypt_file(Task("encrypt", input_path.string()), password);

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

  const auto password =
      detail::Password("alongsentencepasswordiseasytoremember");

  detail::encrypt_file(Task("encrypt", input_path.string()), password);
  detail::decrypt_file(Task("decrypt", encrypted_path.string()), password);

  std::ifstream decrypted_file(decrypted_path);
  std::string decrypted_content;
  std::getline(decrypted_file, decrypted_content);

  EXPECT_EQ(decrypted_content, "roundtrip me");

  std::filesystem::remove(input_path);
  std::filesystem::remove(encrypted_path);
  std::filesystem::remove(decrypted_path);
}

}  // namespace

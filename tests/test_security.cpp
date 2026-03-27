#include <gtest/gtest.h>
#include <pty.h>
#include <sodium.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "encrypt_decrypt.hpp"

namespace {

/**
 * @brief Temporarily replaces stdin for tests.
 */
class ScopedStdinRedirect {
 public:
  /**
   * @brief Redirects stdin to a replacement file descriptor.
   * @param replacement_fd File descriptor to expose as stdin.
   */
  explicit ScopedStdinRedirect(int replacement_fd)
      : saved_fd_(dup(STDIN_FILENO)) {
    if (saved_fd_ == -1) {
      throw std::runtime_error("Failed to duplicate stdin");
    }
    if (dup2(replacement_fd, STDIN_FILENO) == -1) {
      close(saved_fd_);
      throw std::runtime_error("Failed to redirect stdin");
    }
  }

  ScopedStdinRedirect(const ScopedStdinRedirect&) = delete;
  auto operator=(const ScopedStdinRedirect&) -> ScopedStdinRedirect& = delete;

  /** @brief Restores the original stdin file descriptor. */
  ~ScopedStdinRedirect() {
    if (saved_fd_ != -1) {
      dup2(saved_fd_, STDIN_FILENO);
      close(saved_fd_);
    }
  }

 private:
  int saved_fd_;
};

/**
 * @brief Runs a task while feeding a password through a pseudo terminal.
 * @param task Task to execute.
 * @param password Password written to stdin.
 */
auto run_task_with_password(const Task& task, const std::string& password)
    -> void {
  int master_fd = -1;
  int slave_fd = -1;
  if (openpty(&master_fd, &slave_fd, nullptr, nullptr, nullptr) == -1) {
    throw std::runtime_error("Failed to create pseudo terminal");
  }

  const std::string input = password + "\n";
  if (write(master_fd, input.data(), input.size()) == -1) {
    close(master_fd);
    close(slave_fd);
    throw std::runtime_error("Failed to write password");
  }

  try {
    {
      ScopedStdinRedirect redirect(slave_fd);
      close(slave_fd);
      std::cin.clear();
      run_task(task);
    }
  } catch (...) {
    close(master_fd);
    throw;
  }

  close(master_fd);
}

/**
 * @brief Reads a whole file into memory for tests.
 * @param path File to read.
 * @return Complete file contents.
 */
auto read_file(const std::filesystem::path& path) -> std::string {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

TEST(PasswordRulesTest, AcceptsLowercasePasswordWithMinimumLength) {
  EXPECT_NO_THROW(detail::Password("alongsentencepasswordiseasytoremember"));
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

TEST(EncryptedFileMetadataTest, UsesExpectedDefaultParameters) {
  const detail::EncryptedFileMetadata metadata;

  EXPECT_EQ(metadata.alg(), crypto_pwhash_ALG_DEFAULT);
  EXPECT_EQ(metadata.opslimit(), crypto_pwhash_OPSLIMIT_INTERACTIVE);
  EXPECT_EQ(metadata.memlimit(), crypto_pwhash_MEMLIMIT_INTERACTIVE);
  EXPECT_EQ(metadata.salt().size(), crypto_pwhash_SALTBYTES);
}

TEST(EncryptedFileMetadataTest, RejectsInvalidAlgorithm) {
  EXPECT_THROW(
      detail::EncryptedFileMetadata(-1, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE),
      std::runtime_error);
}

TEST(EncryptedFileMetadataTest, RejectsInvalidOpslimit) {
  EXPECT_THROW(
      detail::EncryptedFileMetadata(crypto_pwhash_ALG_DEFAULT, 0,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE),
      std::runtime_error);
}

TEST(EncryptedFileMetadataTest, RejectsInvalidMemlimit) {
  EXPECT_THROW(
      detail::EncryptedFileMetadata(crypto_pwhash_ALG_DEFAULT,
                                    crypto_pwhash_OPSLIMIT_INTERACTIVE, 0),
      std::runtime_error);
}

TEST(TaskTest, ParsesEncryptCommand) {
  const Task task("encrypt", "secret.txt");

  EXPECT_EQ(task.command_type, TaskType::Encrypt);
  EXPECT_EQ(task.file_name, "secret.txt");
}

TEST(TaskTest, ParsesDecryptCommand) {
  const Task task("decrypt", "secret.txt.enc");

  EXPECT_EQ(task.command_type, TaskType::Decrypt);
  EXPECT_EQ(task.file_name, "secret.txt.enc");
}

TEST(TaskTest, RejectsUnknownCommand) {
  EXPECT_THROW(Task("dance", "secret.txt"), std::invalid_argument);
}

TEST(RunTaskTest, EncryptsAndDecryptsFileRoundTrip) {
  ASSERT_GE(sodium_init(), 0);

  char temp_dir_template[] = "/tmp/security-roundtrip-XXXXXX";
  const char* temp_dir = mkdtemp(temp_dir_template);
  ASSERT_NE(temp_dir, nullptr);

  const std::filesystem::path input_path =
      std::filesystem::path(temp_dir) / "message.txt";
  const std::string original_text =
      "thisisalonglowercasepayloadwithenoughcontentforaroundtriptest";

  {
    std::ofstream output(input_path, std::ios::binary);
    ASSERT_TRUE(output.is_open());
    output << original_text;
  }

  const std::string password = "alonglowercasepassword";

  ASSERT_NO_THROW(
      run_task_with_password(Task("encrypt", input_path.string()), password));
  ASSERT_NO_THROW(run_task_with_password(
      Task("decrypt", input_path.string() + ".enc"), password));

  EXPECT_EQ(read_file(input_path.string() + ".enc.dec"), original_text);

  std::filesystem::remove_all(temp_dir);
}

}  // namespace

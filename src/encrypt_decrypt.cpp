#include "encrypt_decrypt.hpp"

#include <sodium.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <vector>

namespace {
constexpr std::size_t MIN_LENGTH = 18;

class TerminalSettings {
 public:
  TerminalSettings() {
    // Store current terminal settings
    tcgetattr(STDIN_FILENO, &cur_settings_);
  }
  TerminalSettings(const TerminalSettings &) = delete;
  TerminalSettings(TerminalSettings &&) = delete;
  auto operator=(const TerminalSettings &) -> TerminalSettings & = delete;
  auto operator=(TerminalSettings &&) -> TerminalSettings & = delete;
  ~TerminalSettings() noexcept {
    // Use RAII to auto reset terminal settings if everything explodes
    tcsetattr(STDIN_FILENO, TCSANOW, &cur_settings_);
  };

  auto turn_off_echo() noexcept -> void {
    termios new_settings{cur_settings_};
    new_settings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
  }

 private:
  termios cur_settings_{};
};

class EncryptedFileMetadata {
 public:
  EncryptedFileMetadata(
      int file_alg = crypto_pwhash_ALG_DEFAULT,
      unsigned int file_opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE,
      unsigned int file_memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE)
      : alg_(file_alg), opslimit_(file_opslimit), memlimit_(file_memlimit) {
    randombytes_buf(salt_.data(), salt_.size());
    randombytes_buf(nonce_.data(), nonce_.size());
    validate();
  }

  explicit EncryptedFileMetadata(const std::string &file_name) {
    std::ifstream file_istream(file_name, std::ios::binary);
    if (!file_istream.is_open()) {
      throw std::runtime_error("Cannot open file for reading: " + file_name);
    }

    std::array<char, 4> magic{};
    if (!file_istream.read(magic.data(),
                           static_cast<std::streamsize>(magic.size()))) {
      throw std::runtime_error("Cannot read file magic");
    }
    if (magic != std::array{'S', 'E', 'C', '\n'}) {
      throw std::runtime_error("Invalid file format");
    }
    std::array<char, 4> version{};
    if (!file_istream.read(version.data(),
                           static_cast<std::streamsize>(version.size()))) {
      throw std::runtime_error("Cannot read file version");
    }
    if (version != std::array<char, 4>{'1', '.', '0', '\n'}) {
      throw std::runtime_error("Invalid file version");
    }
    if (!file_istream.read(reinterpret_cast<char *>(&alg_), sizeof(alg_))) {
      throw std::runtime_error("Cannot read algorithm");
    }
    if (!file_istream.read(reinterpret_cast<char *>(&opslimit_),
                           sizeof(opslimit_))) {
      throw std::runtime_error("Cannot read opslimit");
    }
    if (!file_istream.read(reinterpret_cast<char *>(&memlimit_),
                           sizeof(memlimit_))) {
      throw std::runtime_error("Cannot read memlimit");
    }
    if (!file_istream.read(reinterpret_cast<char *>(salt_.data()),
                           static_cast<std::streamsize>(salt_.size()))) {
      throw std::runtime_error("Cannot read salt");
    }
    if (!file_istream.read(reinterpret_cast<char *>(nonce_.data()),
                           static_cast<std::streamsize>(nonce_.size()))) {
      throw std::runtime_error("Cannot read nonce");
    }
    validate();
  }

  [[nodiscard]] auto alg() const noexcept -> int { return alg_; }
  [[nodiscard]] auto opslimit() const noexcept -> unsigned int {
    return opslimit_;
  }
  [[nodiscard]] auto memlimit() const noexcept -> unsigned int {
    return memlimit_;
  }
  [[nodiscard]] auto salt() const noexcept
      -> const std::array<unsigned char, crypto_pwhash_SALTBYTES> & {
    return salt_;
  }
  [[nodiscard]] auto nonce() const noexcept
      -> const std::array<unsigned char, crypto_secretbox_NONCEBYTES> & {
    return nonce_;
  }
  [[nodiscard]] auto size() const noexcept -> std::streamoff {
    return static_cast<std::streamoff>(4 + 4 + sizeof(alg_) +
                                       sizeof(opslimit_) + sizeof(memlimit_) +
                                       salt_.size() + nonce_.size());
  }

  auto write_to_file(const std::string &file_name) const -> void {
    std::ofstream file_ofstream(file_name, std::ios::binary);
    if (!file_ofstream.is_open()) {
      throw std::runtime_error("Cannot open file for writing: " + file_name);
    }
    if (!file_ofstream.write("SEC\n", 4)) {
      throw std::runtime_error("Cannot write file magic");
    }
    if (!file_ofstream.write("1.0\n", 4)) {
      throw std::runtime_error("Cannot write file version");
    }
    if (!file_ofstream.write(reinterpret_cast<const char *>(&alg_),
                             sizeof(alg_))) {
      throw std::runtime_error("Cannot write algorithm id");
    }
    if (!file_ofstream.write(reinterpret_cast<const char *>(&opslimit_),
                             sizeof(opslimit_))) {
      throw std::runtime_error("Cannot write opslimit");
    }
    if (!file_ofstream.write(reinterpret_cast<const char *>(&memlimit_),
                             sizeof(memlimit_))) {
      throw std::runtime_error("Cannot write memlimit");
    }

    for (const auto &salt_ch : salt_) {
      if (!file_ofstream.write(reinterpret_cast<const char *>(&salt_ch),
                               sizeof(salt_ch))) {
        throw std::runtime_error("Cannot write salt");
      }
    }
    for (const auto &nonce_ch : nonce_) {
      if (!file_ofstream.write(reinterpret_cast<const char *>(&nonce_ch),
                               sizeof(nonce_ch))) {
        throw std::runtime_error("Cannot write nonce");
      }
    }
  }

 private:
  auto validate() const -> void {
    static const std::array<int, 3> ValidAlgorithms{
        crypto_pwhash_ALG_ARGON2I13, crypto_pwhash_ALG_ARGON2ID13,
        crypto_pwhash_ALG_DEFAULT};
    static const std::array<unsigned int, 3> ValidOpslimits{
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_OPSLIMIT_SENSITIVE};
    static const std::array<unsigned int, 3> ValidMemlimits{
        crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_SENSITIVE};

    if (std::ranges::find(ValidAlgorithms, alg_) == ValidAlgorithms.end()) {
      throw std::runtime_error("Invalid algorithm");
    }
    if (std::ranges::find(ValidOpslimits, opslimit_) == ValidOpslimits.end()) {
      throw std::runtime_error("Invalid opslimit");
    }
    if (std::ranges::find(ValidMemlimits, memlimit_) == ValidMemlimits.end()) {
      throw std::runtime_error("Invalid memlimit");
    }
  }

  int alg_{};
  unsigned int opslimit_{};
  unsigned int memlimit_{};
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt_{};
  std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce_{};
};
}  // namespace

auto encrypt_file(const Task &task, const std::string &password) -> void {
  // Open file
  std::ifstream file_istream(task.file_name, std::ios::binary);
  if (!file_istream.is_open()) {
    throw std::runtime_error("Cannot open file: " + task.file_name);
  }

  // Dump file to vector of chars
  std::vector<unsigned char> file_text{};
  unsigned char buffer = 0;
  while (file_istream.read(reinterpret_cast<char *>(&buffer), 1)) {
    file_text.push_back(buffer);
  }

  // Check the eof was reached properly
  if (!file_istream.eof()) {
    throw std::runtime_error("Cannot read input file: " + task.file_name);
  }

  const EncryptedFileMetadata metadata;

  // derive key from password + metadata (KDF)
  std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};
  if (crypto_pwhash(key.data(), key.size(), password.c_str(), password.length(),
                    metadata.salt().data(), metadata.opslimit(),
                    metadata.memlimit(), metadata.alg()) != 0) {
    throw std::runtime_error("Failed to create key");
  }

  // encrypt file bytes
  std::vector<unsigned char> encrypted_text(file_text.size() +
                                            crypto_secretbox_MACBYTES);
  if (crypto_secretbox_easy(encrypted_text.data(), file_text.data(),
                            file_text.size(), metadata.nonce().data(),
                            key.data()) != 0) {
    throw std::runtime_error("Encryption failed");
  }

  // write file to disk, metadata first, then the actual encrypted text
  const std::string output_file_name = task.file_name + ".enc";
  metadata.write_to_file(output_file_name);
  std::ofstream file_ofstream(output_file_name,
                              std::ios::binary | std::ios::app);
  if (!file_ofstream.is_open()) {
    throw std::runtime_error("Cannot open file for writing: " +
                             output_file_name);
  }
  if (!file_ofstream.write(
          reinterpret_cast<const char *>(encrypted_text.data()),
          static_cast<std::streamsize>(encrypted_text.size()))) {
    throw std::runtime_error("Cannot write encrypted text");
  }
}

auto decrypt_file(const Task &task, const std::string &password) -> void {
  // Load metadata from file
  const auto encrypted_file_metadata = EncryptedFileMetadata(task.file_name);

  // Load encrypted text from file
  std::ifstream file_istream(task.file_name, std::ios::binary);
  if (!file_istream.is_open()) {
    throw std::runtime_error("Cannot open file for reading: " + task.file_name);
  }
  file_istream.seekg(encrypted_file_metadata.size());
  if (!file_istream) {
    throw std::runtime_error("Cannot get to encrypted text");
  }
  std::vector<unsigned char> encrypted_text{};
  unsigned char buffer = 0;
  while (file_istream.read(reinterpret_cast<char *>(&buffer), 1)) {
    encrypted_text.push_back(buffer);
  }
  if (!file_istream.eof()) {
    throw std::runtime_error("Cannot read encrypted text");
  }

  // Generate key
  std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};
  if (crypto_pwhash(key.data(), key.size(), password.c_str(), password.length(),
                    encrypted_file_metadata.salt().data(),
                    encrypted_file_metadata.opslimit(),
                    encrypted_file_metadata.memlimit(),
                    encrypted_file_metadata.alg()) != 0) {
    throw std::runtime_error("Cannot create key");
  }

  // Decrypt file
  std::vector<unsigned char> file_text{};
  if (encrypted_text.size() < crypto_secretbox_MACBYTES) {
    throw std::runtime_error("Encrypted file is too short. Might be damaged.");
  }
  file_text.resize(encrypted_text.size() - crypto_secretbox_MACBYTES);
  if (crypto_secretbox_open_easy(
          file_text.data(), encrypted_text.data(), encrypted_text.size(),
          encrypted_file_metadata.nonce().data(), key.data()) != 0) {
    throw std::runtime_error("Decryption failed");
  }

  // Dump decrypted file on disk.
  std::ofstream file_ofstream(task.file_name + ".dec", std::ios::binary);
  const std::string output_file_name = task.file_name + ".dec";
  if (!file_ofstream.is_open()) {
    throw std::runtime_error("Cannot open file for writing: " +
                             output_file_name);
  }
  if (!file_ofstream.write(reinterpret_cast<const char *>(file_text.data()),
                           static_cast<std::streamsize>(file_text.size()))) {
    throw std::runtime_error("Cannot write decrypted file");
  }
}

auto is_valid_password(const std::string &password) -> bool {
  if (password.length() < MIN_LENGTH) {
    return false;
  }
  return !std::ranges::any_of(password,
                              [](char ch) { return ch < 'a' or ch > 'z'; });
}

auto get_password() -> std::string {
  std::println("Password must be lowercase alphabetic, minimum length is {}",
               MIN_LENGTH);
  std::println("Please insert password: ");

  TerminalSettings terminal_settings;
  terminal_settings.turn_off_echo();

  std::string password;
  int failed_attempts = 0;
  while (failed_attempts < 3) {
    std::cin >> password;

    if (is_valid_password(password)) {
      std::println("Cool, thanks!");
      return password;
    }
    std::println("Invalid password");
    ++failed_attempts;
  }

  throw std::runtime_error("Too many attempts");
}

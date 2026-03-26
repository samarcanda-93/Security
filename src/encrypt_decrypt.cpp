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
#include <cstdint>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr std::size_t CHUNK_SIZE = 4096;

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
      std::int32_t file_alg = crypto_pwhash_ALG_DEFAULT,
      std::uint64_t file_opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE,
      std::uint64_t file_memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE)
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

  [[nodiscard]] auto alg() const noexcept -> std::int32_t { return alg_; }
  [[nodiscard]] auto opslimit() const noexcept -> std::uint64_t {
    return opslimit_;
  }
  [[nodiscard]] auto memlimit() const noexcept -> std::uint64_t {
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
    static const std::array<std::int32_t, 3> ValidAlgorithms{
        crypto_pwhash_ALG_ARGON2I13, crypto_pwhash_ALG_ARGON2ID13,
        crypto_pwhash_ALG_DEFAULT};
    static const std::array<std::uint64_t, 3> ValidOpslimits{
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_OPSLIMIT_SENSITIVE};
    static const std::array<std::uint64_t, 3> ValidMemlimits{
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

  std::int32_t alg_{};
  std::uint64_t opslimit_{};
  std::uint64_t memlimit_{};
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt_{};
  std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce_{};
};

class Key {
 public:
  Key(const detail::Password &password, const EncryptedFileMetadata &metadata) {
    if (crypto_pwhash(key_.data(), key_.size(), password.password().c_str(),
                      password.password().length(), metadata.salt().data(),
                      static_cast<unsigned long long>(metadata.opslimit()),
                      static_cast<std::size_t>(metadata.memlimit()),
                      static_cast<int>(metadata.alg())) != 0) {
      throw std::runtime_error("Failed to create key");
    }
  }
  ~Key() { sodium_memzero(key_.data(), key_.size()); }
  Key(const Key &) = delete;
  Key(Key &&other) noexcept : key_(other.key_) {
    sodium_memzero(other.key_.data(), other.key_.size());
  }
  auto operator=(const Key &) -> Key & = delete;
  auto operator=(Key &&other) noexcept -> Key & {
    if (this != &other) {
      sodium_memzero(key_.data(), key_.size());
      key_ = other.key_;
      sodium_memzero(other.key_.data(), other.key_.size());
    }
    return *this;
  }

  [[nodiscard]] auto key_data() const -> const unsigned char * {
    return key_.data();
  }

 private:
  std::array<unsigned char, crypto_secretbox_KEYBYTES> key_{};
};
}  // namespace

namespace detail {
Password::Password() {
  std::println("Password must be lowercase alphabetic, minimum length is {}",
               MIN_LENGTH);
  std::println("Please insert password: ");

  TerminalSettings terminal_settings;
  terminal_settings.turn_off_echo();

  while (attempts_ < 3) {
    if (!(std::cin >> password_)) {
      throw std::runtime_error("Cannot read password");
    }

    if (is_valid_(password_)) {
      std::println("Cool, thanks!");
      return;
    }
    std::println("Invalid password");
    ++attempts_;
  }

  throw std::runtime_error("Too many attempts");
}

Password::Password(std::string password) : password_(std::move(password)) {
  if (!is_valid_(password_)) {
    throw std::runtime_error("Invalid password");
  }
}

Password::~Password() { sodium_memzero(password_.data(), password_.size()); }

auto Password::password() const -> const std::string & { return password_; }

auto Password::is_valid_(const std::string &password) -> bool {
  return password.length() >= MIN_LENGTH &&
         !std::ranges::any_of(password,
                              [](char ch) { return ch < 'a' or ch > 'z'; });
}
}  // namespace detail

class Encrypter {
 public:
  Encrypter(const std::string &file_name)
      : file_istream_(file_name, std::ios::binary),
        key_(derive_key(metadata_)),
        file_ofstream_(file_name + ".enc", std::ios::binary | std::ios::app),
        output_file_name_(file_name + ".enc") {
    if (!file_istream_.is_open()) {
      throw std::runtime_error("Cannot open file: " + file_name);
    }
    if (!file_ofstream_.is_open()) {
      throw std::runtime_error("Cannot open file for writing: " +
                               output_file_name_);
    }

    // Write metadata to file, once and for all
    metadata_.write_to_file(output_file_name_);
  }

  auto encrypt_file() {
    do {
      encrypt_file_chunk_();
    } while (bytes_read_ == CHUNK_SIZE);
  }

 private:
  static auto derive_key(const EncryptedFileMetadata &metadata) -> Key {
    return {detail::Password(), metadata};
  }

  auto cook_encryption_() const -> std::vector<unsigned char> {
    std::vector<unsigned char> encrypted_text(bytes_read_ +
                                              crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(encrypted_text.data(), file_text_chunk_.data(),
                              bytes_read_, metadata_.nonce().data(),
                              key_.key_data()) != 0) {
      throw std::runtime_error("Encryption failed");
    }

    return encrypted_text;
  }

  auto encrypt_file_chunk_() -> void {
    // Dump chunk to vector of chars
    bytes_read_ = 0;
    for (std::size_t i = 0; i < CHUNK_SIZE; ++i) {
      unsigned char buffer = 0;
      if (file_istream_.read(reinterpret_cast<char *>(&buffer), 1)) {
        file_text_chunk_.at(i) = buffer;
        ++bytes_read_;
      } else {
        break;
      }
    }

    if (bytes_read_ == 0) {
      return;
    }

    encrypted_text_chunk_ = cook_encryption_();

    if (!file_ofstream_.write(
            reinterpret_cast<const char *>(encrypted_text_chunk_.data()),
            static_cast<std::streamsize>(encrypted_text_chunk_.size()))) {
      throw std::runtime_error("Cannot write encrypted chunk");
    }
  }

  std::ifstream file_istream_;
  EncryptedFileMetadata metadata_;
  Key key_;
  std::ofstream file_ofstream_;
  std::string output_file_name_;
  std::size_t bytes_read_{0};
  std::array<unsigned char, CHUNK_SIZE> file_text_chunk_{};
  std::vector<unsigned char> encrypted_text_chunk_;
};

class Decrypter {
 public:
  Decrypter(const std::string &file_name)
      : file_istream_(file_name, std::ios::binary),
        metadata_(file_name),
        key_(derive_key(metadata_)),
        file_ofstream_(file_name + ".dec", std::ios::binary | std::ios::app),
        output_file_name_(file_name + ".dec") {
    if (!file_istream_.is_open()) {
      throw std::runtime_error("Cannot open file: " + file_name);
    }
    if (!file_ofstream_.is_open()) {
      throw std::runtime_error("Cannot open file for writing: " +
                               output_file_name_);
    }

    // Go to read the ecrypted text
    file_istream_.seekg(metadata_.size());
    if (!file_istream_) {
      throw std::runtime_error("Cannot get to encrypted text");
    }
  }

  auto decrypt_file() {
    do {
      decrypt_file_chunk_();
    } while (bytes_read_ == CHUNK_SIZE + crypto_secretbox_MACBYTES);
  }

 private:
  // TODO: Derive key should live outside of the classes.
  static auto derive_key(const EncryptedFileMetadata &metadata) -> Key {
    return Key{detail::Password(), metadata};
  }

  auto cook_decryption_() -> std::vector<unsigned char> {
    if (bytes_read_ < crypto_secretbox_MACBYTES) {
      throw std::runtime_error(
          "Encrypted file is too short. Might be damaged.");
    }
    file_text_chunk_.resize(bytes_read_ - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(
            file_text_chunk_.data(), encrypted_text_chunk_.data(), bytes_read_,
            metadata_.nonce().data(), key_.key_data()) != 0) {
      throw std::runtime_error("Decryption failed");
    }

    return file_text_chunk_;
  }

  auto decrypt_file_chunk_() -> void {
    bytes_read_ = 0;

    for (std::size_t i = 0; i < CHUNK_SIZE + crypto_secretbox_MACBYTES; ++i) {
      unsigned char buffer = 0;
      if (file_istream_.read(reinterpret_cast<char *>(&buffer), 1)) {
        encrypted_text_chunk_.at(i) = buffer;
        ++bytes_read_;
      } else {
        break;
      }
    }

    if (bytes_read_ == 0) {
      return;
    }

    file_text_chunk_ = cook_decryption_();

    if (!file_ofstream_.is_open()) {
      throw std::runtime_error("Cannot open file for writing: " +
                               output_file_name_);
    }

    if (!file_ofstream_.write(
            reinterpret_cast<const char *>(file_text_chunk_.data()),
            static_cast<std::streamsize>(file_text_chunk_.size()))) {
      throw std::runtime_error("Cannot write decrypted chunk");
    }
  }

  std::ifstream file_istream_;
  EncryptedFileMetadata metadata_;
  Key key_;
  std::ofstream file_ofstream_;
  std::string output_file_name_;
  std::size_t bytes_read_{0};
  std::array<unsigned char, CHUNK_SIZE + crypto_secretbox_MACBYTES>
      encrypted_text_chunk_;
  std::vector<unsigned char> file_text_chunk_;
};

auto encrypt_file(const Task &task) -> void {
  Encrypter encrypter(task.file_name);
  encrypter.encrypt_file();
}

auto decrypt_file(const Task &task) -> void {
  Decrypter decrypter(task.file_name);
  decrypter.decrypt_file();
}

namespace detail {
auto encrypt_file(const Task &task, const Password &password) -> void {
  std::ifstream file_istream(task.file_name, std::ios::binary);
  if (!file_istream.is_open()) {
    throw std::runtime_error("Cannot open file: " + task.file_name);
  }

  std::vector<unsigned char> file_text{};
  unsigned char buffer = 0;
  while (file_istream.read(reinterpret_cast<char *>(&buffer), 1)) {
    file_text.push_back(buffer);
  }
  if (!file_istream.eof()) {
    throw std::runtime_error("Cannot read input file: " + task.file_name);
  }

  // TODO: finish the streaming/file-size story
  // TODO: keep sensitive lifetime tight
  // TODO: stabilize the test surface
  // TODO: clean up the current encrypt/decrypt flow

  const EncryptedFileMetadata metadata;
  std::vector<unsigned char> encrypted_text(file_text.size() +
                                            crypto_secretbox_MACBYTES);
  {
    const Key key(password, metadata);
    if (crypto_secretbox_easy(encrypted_text.data(), file_text.data(),
                              file_text.size(), metadata.nonce().data(),
                              key.key_data()) != 0) {
      throw std::runtime_error("Encryption failed");
    }
  }

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

auto decrypt_file(const Task &task, const Password &password) -> void {
  const auto encrypted_file_metadata = EncryptedFileMetadata(task.file_name);

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

  if (encrypted_text.size() < crypto_secretbox_MACBYTES) {
    throw std::runtime_error("Encrypted file is too short. Might be damaged.");
  }

  std::vector<unsigned char> file_text(encrypted_text.size() -
                                       crypto_secretbox_MACBYTES);
  {
    const Key key(password, encrypted_file_metadata);
    if (crypto_secretbox_open_easy(
            file_text.data(), encrypted_text.data(), encrypted_text.size(),
            encrypted_file_metadata.nonce().data(), key.key_data()) != 0) {
      throw std::runtime_error("Decryption failed");
    }
  }

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
}  // namespace detail

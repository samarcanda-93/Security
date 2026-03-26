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
constexpr std::size_t MIN_LENGTH = 8;

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
}  // namespace

auto is_valid_password(const std::string &password) -> bool {
  // if (password.length() < MIN_LENGTH) {
  //   return false;
  // }

  // for (const auto ch : password) {
  //   if (ch < 'a' || ch > 'z') {
  //     return false;
  //   }
  // }

  return password.length() >= MIN_LENGTH &&
         std::ranges::all_of(password,
                             [](char ch) { return ch >= 'a' && ch <= 'z'; });
  ;
}

// TODO: Make file read a stream, not a dump
auto encrypt_file(const Task &task, std::string password) -> void {
  // TODO: Add error handling
  std::ifstream file_istream(task.file_name, std::ios::binary);

  std::vector<unsigned char> file_text{};
  unsigned char buffer = 0;
  while (file_istream.read(reinterpret_cast<char *>(&buffer), 1)) {
    file_text.push_back(buffer);
  }

  // generate salt, a bunch of random metadata that avoids mapping same password
  // to same key
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
  randombytes_buf(salt.data(), sizeof(salt));

  // get key from password
  std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};

  int alg = crypto_pwhash_ALG_DEFAULT;
  unsigned int opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  unsigned int memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;

  if (crypto_pwhash(key.data(), key.size(), password.c_str(), password.length(),
                    salt.data(), opslimit, memlimit, alg) != 0) {
    throw std::runtime_error("Failed to create key");
  }

  // generate nonce
  std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
  randombytes_buf(nonce.data(), nonce.size());

  // encrypt file bytes
  std::vector<unsigned char> encrypted_text(file_text.size() +
                                            crypto_secretbox_MACBYTES);

  if (crypto_secretbox_easy(encrypted_text.data(), file_text.data(),
                            file_text.size(), nonce.data(), key.data()) != 0) {
    throw std::runtime_error("Encryption failed");
  }

  std::ofstream file_ofstream(task.file_name + ".enc", std::ios::binary);
  file_ofstream.write("SEC\n", 4);
  file_ofstream.write("1.0\n", 4);
  // TODO: Figure out how to avoid reinterpret_cast
  file_ofstream.write(reinterpret_cast<const char *>(&alg), sizeof(alg));
  file_ofstream.write(reinterpret_cast<const char *>(&opslimit),
                      sizeof(opslimit));
  file_ofstream.write(reinterpret_cast<const char *>(&memlimit),
                      sizeof(memlimit));

  for (const auto &salt_ch : salt) {
    file_ofstream.write(reinterpret_cast<const char *>(&salt_ch),
                        sizeof(salt_ch));
  }
  for (const auto &nonce_ch : nonce) {
    file_ofstream.write(reinterpret_cast<const char *>(&nonce_ch),
                        sizeof(nonce_ch));
  }
  for (const auto &enc_ch : encrypted_text) {
    file_ofstream.write(reinterpret_cast<const char *>(&enc_ch),
                        sizeof(enc_ch));
  }
}

auto decrypt_file(const Task &task, std::string password) -> void {
  // Read encrypted file
  std::ifstream file_istream(task.file_name, std::ios::binary);

  std::array<char, 4> magic{};
  file_istream.read(magic.data(), magic.size());
  if (magic != std::array{'S', 'E', 'C', '\n'}) {
    throw std::runtime_error("Invalid file format");
  }

  std::array<char, 4> version{};
  file_istream.read(version.data(), version.size());
  if (version != std::array<char, 4>{'1', '.', '0', '\n'}) {
    throw std::runtime_error("Invalid file version");
  }

  int alg{};
  file_istream.read(reinterpret_cast<char *>(&alg), sizeof(alg));
  unsigned int opslimit{};
  file_istream.read(reinterpret_cast<char *>(&opslimit), sizeof(opslimit));
  unsigned int memlimit{};
  file_istream.read(reinterpret_cast<char *>(&memlimit), sizeof(memlimit));
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
  file_istream.read(reinterpret_cast<char *>(salt.data()), salt.size());
  std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
  file_istream.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
  std::vector<unsigned char> enc_chars{};
  unsigned char buffer = 0;
  while (file_istream.read(reinterpret_cast<char *>(&buffer), 1)) {
    enc_chars.push_back(buffer);
  }

  // Generate key
  std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};
  if (crypto_pwhash(key.data(), key.size(), password.c_str(), password.length(),
                    salt.data(), opslimit, memlimit, alg) != 0) {
    throw std::runtime_error("Failed to create key");
  }

  // Decrypt file
  std::vector<unsigned char> file_text{};
  if (enc_chars.size() < crypto_secretbox_MACBYTES) {
    throw std::runtime_error("Encrypted file is too short. Might be damaged.");
  }
  file_text.resize(enc_chars.size() - crypto_secretbox_MACBYTES);
  if (crypto_secretbox_open_easy(file_text.data(), enc_chars.data(),
                                 enc_chars.size(), nonce.data(),
                                 key.data()) != 0) {
    throw std::runtime_error("Decryption failed");
  }

  // Dump decrypted file on disk.
  std::ofstream file_ofstream(task.file_name + ".dec", std::ios::binary);
  file_ofstream.write(reinterpret_cast<const char *>(file_text.data()),
                      static_cast<std::streamsize>(file_text.size()));
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
    ++failed_attempts;
  }

  throw std::runtime_error("Too many attempts");
}

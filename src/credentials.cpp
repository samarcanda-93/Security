#include "credentials.hpp"

#include <sodium.h>
#include <sodium/crypto_pwhash.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

#include "encrypt_decrypt.hpp"

namespace {
class TerminalSettings {
 public:
  TerminalSettings() {
    // Store current terminal settings
    // TODO: Terminal settings return check
    tcgetattr(STDIN_FILENO, &cur_settings_);
  }
  TerminalSettings(const TerminalSettings&) = delete;
  TerminalSettings(TerminalSettings&&) = delete;
  auto operator=(const TerminalSettings&) -> TerminalSettings& = delete;
  auto operator=(TerminalSettings&&) -> TerminalSettings& = delete;
  ~TerminalSettings() noexcept {
    // Use RAII to auto reset terminal settings if everything explodes
    tcsetattr(STDIN_FILENO, TCSANOW, &cur_settings_);
  };

  auto turn_off_echo() noexcept -> void {
    termios new_settings{cur_settings_};
    new_settings.c_lflag &= ~ECHO;
    // TODO: Terminal settings return check
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
  }

 private:
  termios cur_settings_{};
};
}  // namespace

namespace detail {
Key::Key(const Password& password, const EncryptedFileMetadata& metadata) {
  if (crypto_pwhash(key_.data(), key_.size(), password.password().c_str(),
                    password.password().length(), metadata.salt().data(),
                    static_cast<unsigned long long>(metadata.opslimit()),
                    static_cast<std::size_t>(metadata.memlimit()),
                    static_cast<int>(metadata.alg())) != 0) {
    throw std::runtime_error("Failed to create key");
  }
}

Key::~Key() { sodium_memzero(key_.data(), key_.size()); }

Key::Key(Key&& other) noexcept : key_(other.key_) {
  sodium_memzero(other.key_.data(), other.key_.size());
}

auto Key::operator=(Key&& other) noexcept -> Key& {
  if (this != &other) {
    sodium_memzero(key_.data(), key_.size());
    key_ = other.key_;
    sodium_memzero(other.key_.data(), other.key_.size());
  }
  return *this;
}

auto Key::key_data() const -> const unsigned char* { return key_.data(); }

Password::Password() {
  std::println("Password must be lowercase alphabetic, minimum length is {}",
               MIN_LENGTH);
  std::println("Please insert password: ");

  TerminalSettings terminal_settings;
  terminal_settings.turn_off_echo();

  while (attempts_ < 3) {
    // TODO: std::array<char, 256> password{}; for password
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

auto Password::password() const -> const std::string& { return password_; }

auto Password::is_valid_(const std::string& password) -> bool {
  return password.length() >= MIN_LENGTH &&
         !std::ranges::any_of(password,
                              [](char ch) { return ch < 'a' or ch > 'z'; });
}
}  // namespace detail

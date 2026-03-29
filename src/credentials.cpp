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
/**
 * @brief Represent terminal settings during password input.
 */
class TerminalSettings {
 public:
  /** @brief Captures the current terminal configuration. */
  TerminalSettings() {
    // Store current terminal settings
    if (tcgetattr(STDIN_FILENO, &cur_settings_) == -1) {
      throw std::runtime_error("Cannot get terminal settings");
    };
  }
  TerminalSettings(const TerminalSettings&) = delete;
  TerminalSettings(TerminalSettings&&) = delete;
  auto operator=(const TerminalSettings&) -> TerminalSettings& = delete;
  auto operator=(TerminalSettings&&) -> TerminalSettings& = delete;
  /** @brief Uses RAII to restore the original terminal configuration. */
  ~TerminalSettings() { tcsetattr(STDIN_FILENO, TCSANOW, &cur_settings_); }

  /** @brief Disables terminal echo while the password is entered. */
  auto turn_off_echo() -> void {
    termios new_settings{cur_settings_};
    new_settings.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_settings) == -1) {
      throw std::runtime_error("Cannot change terminal settings");
    }
  }

 private:
  termios cur_settings_{};
};
}  // namespace

namespace detail {
/**
 * @brief Derives a symmetric key from a password and metadata.
 */
Key::Key(const Password& password, const EncryptedFileMetadata& metadata) {
  if (crypto_pwhash(key_.data(), key_.size(), password.password().c_str(),
                    password.password().length(), metadata.salt().data(),
                    static_cast<unsigned long long>(metadata.opslimit()),
                    static_cast<std::size_t>(metadata.memlimit()),
                    static_cast<int>(metadata.alg())) != 0) {
    throw std::runtime_error("Failed to create key");
  }
}

/** @brief Clears the derived key buffer from memory. */
Key::~Key() { sodium_memzero(key_.data(), key_.size()); }

/** @brief Moves key out of another key instance. */
Key::Key(Key&& other) noexcept : key_(other.key_) {
  sodium_memzero(other.key_.data(), other.key_.size());
}

/** @brief Replaces this key with key from another instance. */
auto Key::operator=(Key&& other) noexcept -> Key& {
  if (this != &other) {
    sodium_memzero(key_.data(), key_.size());
    key_ = other.key_;
    sodium_memzero(other.key_.data(), other.key_.size());
  }
  return *this;
}

/** @brief Returns the raw key pointer expected by libsodium. */
auto Key::key_data() const -> const unsigned char* { return key_.data(); }

/** @brief Prompts for a password until a valid value is entered or retries end.
 */
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

/** @brief Validates and stores a password supplied by the caller. */
Password::Password(std::string password) : password_(std::move(password)) {
  if (!is_valid_(password_)) {
    throw std::runtime_error("Invalid password");
  }
}

/** @brief Clears the stored password contents from memory. */
Password::~Password() { sodium_memzero(password_.data(), password_.size()); }

/** @brief Exposes the validated password string. */
auto Password::password() const -> const std::string& { return password_; }

/** @brief Checks the lowercase-only minimum-length password policy. */
auto Password::is_valid_(const std::string& password) -> bool {
  return password.length() >= MIN_LENGTH &&
         !std::ranges::any_of(password,
                              [](char ch) { return ch < 'a' or ch > 'z'; });
}
}  // namespace detail

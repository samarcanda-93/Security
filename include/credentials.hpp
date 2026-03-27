#pragma once

#include <sodium/crypto_secretbox.h>

#include <array>
#include <string>

namespace detail {
/**
 * @brief Owns metadata required to derive an encryption key from a password.
 */
class EncryptedFileMetadata;

/**
 * @brief Stores and validates a user password.
 */
class Password {
 public:
  /** @brief Prompts the user for a valid password. */
  Password();
  /** @brief Clears the stored password from memory. */
  ~Password();
  Password(const Password&) = delete;
  Password(Password&&) = delete;
  auto operator=(const Password&) -> Password& = delete;
  auto operator=(Password&&) -> Password& = delete;
  /**
   * @brief Builds a password from an already available string.
   * @param password Candidate password to validate.
   */
  explicit Password(std::string password);

  /**
   * @brief Returns the validated password text.
   * @return Immutable reference to the stored password.
   */
  [[nodiscard]] auto password() const -> const std::string&;

 private:
  /**
   * @brief Checks whether a password matches project rules.
   * @param password Password to validate.
   * @return True when the password is accepted.
   */
  static auto is_valid_(const std::string& password) -> bool;

  std::string password_;
  int attempts_ = 0;
  static constexpr std::size_t MIN_LENGTH = 18;
};

/**
 * @brief Owns a libsodium symmetric key.
 */
class Key {
 public:
  /**
   * @brief Derives a key from a password and file metadata.
   * @param password Password used for key derivation.
   * @param metadata Metadata for the derivation.
   */
  Key(const Password& password, const EncryptedFileMetadata& metadata);
  /** @brief Clears the derived key from memory. */
  ~Key();
  Key(const Key&) = delete;
  /** @brief Transfers ownership of key. */
  Key(Key&& other) noexcept;
  auto operator=(const Key&) -> Key& = delete;
  /** @brief Transfers ownership of key. */
  auto operator=(Key&& other) noexcept -> Key&;

  /**
   * @brief Exposes the raw key bytes for libsodium operations.
   * @return Pointer to the beginning of the key buffer.
   */
  [[nodiscard]] auto key_data() const -> const unsigned char*;

 private:
  std::array<unsigned char, crypto_secretbox_KEYBYTES> key_{};
};
}  // namespace detail

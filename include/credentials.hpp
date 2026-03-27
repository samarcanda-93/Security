#pragma once

#include <sodium/crypto_secretbox.h>

#include <array>
#include <string>

namespace detail {
class EncryptedFileMetadata;

class Password {
 public:
  Password();
  ~Password();
  Password(const Password&) = delete;
  Password(Password&&) = delete;
  auto operator=(const Password&) -> Password& = delete;
  auto operator=(Password&&) -> Password& = delete;
  explicit Password(std::string password);

  [[nodiscard]] auto password() const -> const std::string&;

 private:
  static auto is_valid_(const std::string& password) -> bool;

  std::string password_;
  int attempts_ = 0;
  static constexpr std::size_t MIN_LENGTH = 18;
};

class Key {
 public:
  Key(const Password& password, const EncryptedFileMetadata& metadata);
  ~Key();
  Key(const Key&) = delete;
  Key(Key&& other) noexcept;
  auto operator=(const Key&) -> Key& = delete;
  auto operator=(Key&& other) noexcept -> Key&;

  [[nodiscard]] auto key_data() const -> const unsigned char*;

 private:
  std::array<unsigned char, crypto_secretbox_KEYBYTES> key_{};
};
}  // namespace detail

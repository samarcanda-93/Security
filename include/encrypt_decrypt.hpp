#pragma once

#include <string>

#include "command.hpp"

auto encrypt_file(const Task& task) -> void;
auto decrypt_file(const Task& task) -> void;

namespace detail {
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

auto encrypt_file(const Task& task, const Password& password) -> void;
auto decrypt_file(const Task& task, const Password& password) -> void;
}  // namespace detail

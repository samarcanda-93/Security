#pragma once

#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>

#include <array>
#include <cstdint>
#include <ios>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "credentials.hpp"

enum class TaskType : u_int8_t {
  Encrypt,
  Decrypt,
};

struct Task {
 public:
  Task(const std::string& command_name, const std::string& file_name)
      : file_name(file_name) {
    if (command_name == "encrypt") {
      command_type = TaskType::Encrypt;
    } else if (command_name == "decrypt") {
      command_type = TaskType::Decrypt;
    } else {
      throw std::invalid_argument("Don't know this command: " + command_name);
    }
  }

  TaskType command_type;
  std::string file_name;
};

auto run_task(const Task& task) -> void;

namespace detail {
class EncryptedFileMetadata {
 public:
  EncryptedFileMetadata(
      std::int32_t file_alg = crypto_pwhash_ALG_DEFAULT,
      std::uint64_t file_opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE,
      std::uint64_t file_memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE);
  EncryptedFileMetadata(
      std::int32_t file_alg, std::uint64_t file_opslimit,
      std::uint64_t file_memlimit,
      std::array<unsigned char, crypto_pwhash_SALTBYTES> file_salt);

  [[nodiscard]] auto alg() const noexcept -> std::int32_t { return alg_; }
  [[nodiscard]] auto opslimit() const noexcept -> std::uint64_t {
    return opslimit_;
  }
  [[nodiscard]] auto memlimit() const noexcept -> std::uint64_t {
    return memlimit_;
  }
  [[nodiscard]] auto salt() const noexcept
      -> const std::array<unsigned char, crypto_pwhash_SALTBYTES>& {
    return salt_;
  }

  [[nodiscard]] auto size() const noexcept -> std::streamoff {
    return static_cast<std::streamoff>(4 + 4 + sizeof(alg_) +
                                       sizeof(opslimit_) + sizeof(memlimit_) +
                                       salt_.size());
  }

 private:
  auto validate_() const -> void;

  std::int32_t alg_{};
  std::uint64_t opslimit_{};
  std::uint64_t memlimit_{};
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt_{};
};
}  // namespace detail

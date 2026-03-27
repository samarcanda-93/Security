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

/**
 * @brief Describes the supported high-level command types.
 */
enum class TaskType : u_int8_t {
  Encrypt,
  Decrypt,
};

/**
 * @brief Parsed command-line task definition.
 */
struct Task {
 public:
  /**
   * @brief Builds a task from the command name and file name.
   * @param command_name Either `encrypt` or `decrypt`.
   * @param file_name Path of the file to process.
   */
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

/**
 * @brief Executes the requested encryption or decryption task.
 * @param task Parsed task to run.
 */
auto run_task(const Task& task) -> void;

namespace detail {
/**
 * @brief Header metadata stored at the beginning of encrypted files.
 */
class EncryptedFileMetadata {
 public:
  /**
   * @brief Creates metadata with a random salt.
   * @param file_alg Password hashing algorithm identifier.
   * @param file_opslimit Password hashing operations limit.
   * @param file_memlimit Password hashing memory limit.
   */
  EncryptedFileMetadata(
      std::int32_t file_alg = crypto_pwhash_ALG_DEFAULT,
      std::uint64_t file_opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE,
      std::uint64_t file_memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE);
  /**
   * @brief Creates metadata from explicit serialized values.
   * @param file_alg Password hashing algorithm identifier.
   * @param file_opslimit Password hashing operations limit.
   * @param file_memlimit Password hashing memory limit.
   * @param file_salt Salt used for key derivation.
   */
  EncryptedFileMetadata(
      std::int32_t file_alg, std::uint64_t file_opslimit,
      std::uint64_t file_memlimit,
      std::array<unsigned char, crypto_pwhash_SALTBYTES> file_salt);

  /** @brief Returns the password hashing algorithm id. */
  [[nodiscard]] auto alg() const noexcept -> std::int32_t { return alg_; }
  /** @brief Returns the password hashing opslimit. */
  [[nodiscard]] auto opslimit() const noexcept -> std::uint64_t {
    return opslimit_;
  }
  /** @brief Returns the password hashing memlimit. */
  [[nodiscard]] auto memlimit() const noexcept -> std::uint64_t {
    return memlimit_;
  }
  /** @brief Returns the password hashing salt. */
  [[nodiscard]] auto salt() const noexcept
      -> const std::array<unsigned char, crypto_pwhash_SALTBYTES>& {
    return salt_;
  }

  /** @brief Returns the serialized metadata size in bytes. */
  [[nodiscard]] auto size() const noexcept -> std::streamoff {
    return static_cast<std::streamoff>(4 + 4 + sizeof(alg_) +
                                       sizeof(opslimit_) + sizeof(memlimit_) +
                                       salt_.size());
  }

 private:
  /** @brief Validates that all metadata fields use accepted values. */
  auto validate_() const -> void;

  std::int32_t alg_{};
  std::uint64_t opslimit_{};
  std::uint64_t memlimit_{};
  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt_{};
};
}  // namespace detail

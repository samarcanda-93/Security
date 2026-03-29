#include "encrypt_decrypt.hpp"

#include <sodium.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr std::size_t CHUNK_SIZE = 4096;
constexpr std::size_t ENCRYPTED_CHUNK_SIZE =
    CHUNK_SIZE + crypto_secretbox_MACBYTES;

/**
 * @brief Prompts for a password and derives the file key.
 * @param metadata Metadata containing derivation parameters.
 * @return Derived symmetric key.
 */
auto derive_key(const detail::EncryptedFileMetadata &metadata) -> detail::Key {
  return {detail::Password(), metadata};
}

}  // namespace

namespace detail {
/** @brief Builds metadata for a new encrypted file and generates a fresh salt.
 */
EncryptedFileMetadata::EncryptedFileMetadata(std::int32_t file_alg,
                                             std::uint64_t file_opslimit,
                                             std::uint64_t file_memlimit)
    : alg_(file_alg), opslimit_(file_opslimit), memlimit_(file_memlimit) {
  randombytes_buf(salt_.data(), salt_.size());
  validate_();
}

/** @brief Builds metadata from values read from an encrypted file header. */
EncryptedFileMetadata::EncryptedFileMetadata(
    std::int32_t file_alg, std::uint64_t file_opslimit,
    std::uint64_t file_memlimit,
    std::array<unsigned char, crypto_pwhash_SALTBYTES> file_salt)
    : alg_(file_alg),
      opslimit_(file_opslimit),
      memlimit_(file_memlimit),
      salt_(file_salt) {
  validate_();
}

/** @brief Ensures metadata contains only supported password hashing settings.
 */
auto EncryptedFileMetadata::validate_() const -> void {
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

}  // namespace detail

/**
 * @brief Template for encryption and decryption algorithms.
 */
class AbstractCryptoAlgorithm {
 public:
  /** @brief Runs the full chunk-processing loop. */
  auto execute() -> void {
    while (true) {
      read_chunk_();
      if (chunk_is_empty_()) {
        break;
      }
      cook_chunk_();
      write_chunk_();
      if (is_last_chunk_()) {
        break;
      }
    }
  }

  AbstractCryptoAlgorithm(const AbstractCryptoAlgorithm &) = delete;
  AbstractCryptoAlgorithm(AbstractCryptoAlgorithm &&) = delete;
  auto operator=(const AbstractCryptoAlgorithm &)
      -> AbstractCryptoAlgorithm & = delete;
  auto operator=(AbstractCryptoAlgorithm &&)
      -> AbstractCryptoAlgorithm & = delete;
  /** @brief Virtual destructor for polymorphic cleanup. */
  virtual ~AbstractCryptoAlgorithm() = default;

 protected:
  /**
   * @brief Opens the input and output files for a crypto operation.
   * @param input_file_name Source file path.
   * @param output_file_name Destination file path.
   * @param chunk_size Number of bytes processed per iteration.
   */
  AbstractCryptoAlgorithm(const std::string &input_file_name,
                          const std::string &output_file_name,
                          std::size_t chunk_size)
      : file_istream_(input_file_name, std::ios::binary),
        file_ofstream_(output_file_name, std::ios::binary),
        output_file_name_(output_file_name),
        chunk_size_(chunk_size) {
    if (!file_istream_.is_open()) {
      throw std::runtime_error("Cannot open file: " + input_file_name);
    }
    if (!file_ofstream_.is_open()) {
      throw std::runtime_error("Cannot open file for writing: " +
                               output_file_name_);
    }
  }

  virtual auto read_chunk_() -> void = 0;
  virtual auto cook_chunk_() -> void = 0;
  virtual auto write_chunk_() -> void = 0;
  /** @brief Returns whether the current chunk is empty. */
  [[nodiscard]] auto chunk_is_empty_() const -> bool {
    return bytes_read_ == 0;
  }
  /** @brief Returns whether the current chunk is the last one in the stream. */
  [[nodiscard]] auto is_last_chunk_() const -> bool {
    return bytes_read_ < chunk_size_;
  }

  std::ifstream file_istream_;
  std::ofstream file_ofstream_;
  std::string output_file_name_;
  std::size_t bytes_read_{0};
  std::size_t chunk_size_{0};
  std::array<unsigned char, crypto_secretbox_NONCEBYTES> chunk_nonce_{};
};

/**
 * @brief Encrypts a cleartext file.
 */
class Encrypter final : public AbstractCryptoAlgorithm {
 public:
  /**
   * @brief Creates an encrypter for a source file.
   * @param file_name Cleartext file to encrypt.
   */
  Encrypter(const std::string &file_name)
      : AbstractCryptoAlgorithm(file_name, file_name + ".enc", CHUNK_SIZE),
        key_(derive_key(metadata_)) {
    write_metadata_();
  }

 private:
  /** @brief Writes the encrypted file header before ciphertext chunks. */
  auto write_metadata_() -> void {
    const auto alg = metadata_.alg();
    const auto opslimit = metadata_.opslimit();
    const auto memlimit = metadata_.memlimit();

    if (!file_ofstream_.write("SEC\n", 4)) {
      throw std::runtime_error("Cannot write file magic");
    }
    if (!file_ofstream_.write("1.0\n", 4)) {
      throw std::runtime_error("Cannot write file version");
    }
    if (!file_ofstream_.write(reinterpret_cast<const char *>(&alg),
                              sizeof(alg))) {
      throw std::runtime_error("Cannot write algorithm id");
    }
    if (!file_ofstream_.write(reinterpret_cast<const char *>(&opslimit),
                              sizeof(opslimit))) {
      throw std::runtime_error("Cannot write opslimit");
    }
    if (!file_ofstream_.write(reinterpret_cast<const char *>(&memlimit),
                              sizeof(memlimit))) {
      throw std::runtime_error("Cannot write memlimit");
    }
    if (!file_ofstream_.write(
            reinterpret_cast<const char *>(metadata_.salt().data()),
            static_cast<std::streamsize>(metadata_.salt().size()))) {
      throw std::runtime_error("Cannot write salt");
    }
  }

  /** @brief Reads the next chunk from the source file. */
  auto read_chunk_() -> void override {
    file_istream_.read(reinterpret_cast<char *>(file_text_chunk_.data()),
                       static_cast<std::streamsize>(file_text_chunk_.size()));
    bytes_read_ = static_cast<std::size_t>(file_istream_.gcount());
  }

  /** @brief Encrypts the current chunk. */
  auto cook_chunk_() -> void override {
    if (bytes_read_ == 0) {
      encrypted_text_chunk_.clear();
      return;
    }

    randombytes_buf(chunk_nonce_.data(), chunk_nonce_.size());

    encrypted_text_chunk_.resize(bytes_read_ + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(encrypted_text_chunk_.data(),
                              file_text_chunk_.data(), bytes_read_,
                              chunk_nonce_.data(), key_.key_data()) != 0) {
      throw std::runtime_error("Encryption failed");
    }
  }

  /** @brief Writes the nonce and ciphertext for the current chunk. */
  auto write_chunk_() -> void override {
    if (!file_ofstream_.write(
            reinterpret_cast<const char *>(chunk_nonce_.data()),
            static_cast<std::streamsize>(chunk_nonce_.size()))) {
      throw std::runtime_error("Cannot write chunk nonce");
    }

    if (!file_ofstream_.write(
            reinterpret_cast<const char *>(encrypted_text_chunk_.data()),
            static_cast<std::streamsize>(encrypted_text_chunk_.size()))) {
      throw std::runtime_error("Cannot write encrypted chunk");
    }
  }

  detail::EncryptedFileMetadata metadata_;
  detail::Key key_;
  std::array<unsigned char, CHUNK_SIZE> file_text_chunk_{};
  std::vector<unsigned char> encrypted_text_chunk_;
};

/**
 * @brief Decrypts an encrypted file back to plaintext.
 */
class Decrypter final : public AbstractCryptoAlgorithm {
 public:
  /**
   * @brief Creates a decrypter for an encrypted file.
   * @param file_name Encrypted file to decrypt.
   */
  Decrypter(const std::string &file_name)
      : AbstractCryptoAlgorithm(file_name, file_name + ".dec",
                                ENCRYPTED_CHUNK_SIZE),
        metadata_(load_metadata_(file_name)),
        key_(derive_key(metadata_)) {
    // Go to read the encrypted text
    file_istream_.seekg(metadata_.size());
    if (!file_istream_) {
      throw std::runtime_error("Cannot get to encrypted text");
    }
  }

 private:
  /**
   * @brief Reads and validates metadata from an encrypted file header.
   * @param file_name Encrypted file to inspect.
   * @return EncryptedFileMetadata object.
   */
  static auto load_metadata_(const std::string &file_name)
      -> detail::EncryptedFileMetadata {
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

    std::int32_t alg = 0;
    std::uint64_t opslimit = 0;
    std::uint64_t memlimit = 0;
    std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};

    if (!file_istream.read(reinterpret_cast<char *>(&alg), sizeof(alg))) {
      throw std::runtime_error("Cannot read algorithm");
    }
    if (!file_istream.read(reinterpret_cast<char *>(&opslimit),
                           sizeof(opslimit))) {
      throw std::runtime_error("Cannot read opslimit");
    }
    if (!file_istream.read(reinterpret_cast<char *>(&memlimit),
                           sizeof(memlimit))) {
      throw std::runtime_error("Cannot read memlimit");
    }
    if (!file_istream.read(reinterpret_cast<char *>(salt.data()),
                           static_cast<std::streamsize>(salt.size()))) {
      throw std::runtime_error("Cannot read salt");
    }

    return {alg, opslimit, memlimit, salt};
  }

  /** @brief Reads the next nonce and ciphertext chunk from the source file. */
  auto read_chunk_() -> void override {
    bytes_read_ = 0;

    file_istream_.read(reinterpret_cast<char *>(chunk_nonce_.data()),
                       static_cast<std::streamsize>(chunk_nonce_.size()));
    const auto nonce_bytes_read = file_istream_.gcount();

    if (nonce_bytes_read == 0) {
      return;
    }
    if (nonce_bytes_read != static_cast<std::streamsize>(chunk_nonce_.size())) {
      throw std::runtime_error("Truncated chunk nonce");
    }

    file_istream_.read(
        reinterpret_cast<char *>(encrypted_text_chunk_.data()),
        static_cast<std::streamsize>(encrypted_text_chunk_.size()));
    bytes_read_ = static_cast<std::size_t>(file_istream_.gcount());

    if (bytes_read_ == 0) {
      throw std::runtime_error("Missing ciphertext after chunk nonce");
    }
  }

  /** @brief Decrypts the currently loaded ciphertext chunk. */
  auto cook_chunk_() -> void override {
    if (bytes_read_ == 0) {
      file_text_chunk_.clear();
      return;
    }

    if (bytes_read_ < crypto_secretbox_MACBYTES) {
      throw std::runtime_error(
          "Encrypted file is too short. Might be damaged.");
    }
    file_text_chunk_.resize(bytes_read_ - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(file_text_chunk_.data(),
                                   encrypted_text_chunk_.data(), bytes_read_,
                                   chunk_nonce_.data(), key_.key_data()) != 0) {
      throw std::runtime_error("Decryption failed");
    }
  }

  /** @brief Writes the decrypted plaintext chunk to the output file. */
  auto write_chunk_() -> void override {
    if (!file_ofstream_.write(
            reinterpret_cast<const char *>(file_text_chunk_.data()),
            static_cast<std::streamsize>(file_text_chunk_.size()))) {
      throw std::runtime_error("Cannot write decrypted chunk");
    }
  }

  detail::EncryptedFileMetadata metadata_;
  detail::Key key_;
  std::array<unsigned char, ENCRYPTED_CHUNK_SIZE> encrypted_text_chunk_{};
  std::vector<unsigned char> file_text_chunk_;
};

/** @brief Dispatches a task to the corresponding algorithm. */
auto run_task(const Task &task) -> void {
  switch (task.command_type) {
    case TaskType::Encrypt: {
      Encrypter encrypter(task.file_name);
      encrypter.execute();
      break;
    }
    case TaskType::Decrypt: {
      Decrypter decrypter(task.file_name);
      decrypter.execute();
      break;
    }
  }
}

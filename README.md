# Security

**Author:** G. Accorto

A command-line tool that encrypts and decrypts files. A symmetric key is derived
from a user password with `crypto_pwhash` and processes files in chunks with
`crypto_secretbox`.

## Implementation

The program offers two modes:

1. `encrypt <file>` reads a cleartext file and writes `<file>.enc`
2. `decrypt <file>` reads an encrypted file and writes `<file>.dec`

To achieve this, the pipeline is the following:

- Read and store the command-line arguments, storing task and file name in a
  Task object, which is charged with their validation.
- Dispatch the command to an abstract algorithm that subclasses to the matching
  concrete algorithm for encryption or decryption.
- These objects are in charge of reading, loading, and generating the necessary
  objects (input file, EncryptedFileMetadata, Key) and then of performing the
  fixed-size chunk encryption/decryption. They are also in charge of writing the
  streaming output to disk. The lifetime of what I think is the second most
  sensitive information, Key, is limited to the lifetime of these objects.
- In order to minimize the lifetime of the password in the code, the password
  string is owned only by a small derive_key method, called by the abstract
  algorithm. This way the password is asked for right where it's needed, used to
  generate Key, and thrown away immediately.
- To hide the user input while typing the password I used a TerminalSettings
  object that acquires terminal settings, allows turning off terminal echo, and
  restores the settings when it goes out of scope. In this way, the cleanup
  guarantees that the terminal settings are restored via RAII even if the
  program throws an exception.
- The Password and Key objects use libsodium memzero on their data during
  destruction.

## Assumptions and Limitations

- Encryption creates <file>.enc and decryption creates <file>.enc.dec. That
  saves the reader from guessing what files appear on disk, and help
  understanding how many layers of encryption/decryption were applied.
- Encrypted files begin with metadata containing a magic header and version,
  encryption algorithm details, and the salt used for the key derivation. This
  metadata is used to derive back the key during decryption.
- `crypto_secretbox` needs a different nonce for every encryption operation, and
  each file chunk is a separate encryption operation. This avoids reusing the
  same nonce for multiple messages. Therefore each encrypted chunk is composed
  of nonce data and actual ciphertext. While there are probably better tools for
  the job, I didn't want to dig too much in libsodium.
- I decided to enforce a strict password policy to simplify validation. Only
  lowercase alphabetic passwords are accepted, with a minimum length of 18
  specified by MIN_LENGTH.

## Testing

Tests cover:

- password validation rules
- task parsing
- metadata validation
- an e2e encrypt/decrypt round trip

## Requirements

- C++23 compiler and standard library.
- CMake 3.28 or newer
- GoogleTest
- libsodium

Run tests with

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Build and Run

```bash
cmake -S . -B build
cmake --build build
./build/Security encrypt path/to/file
./build/Security decrypt path/to/file
```

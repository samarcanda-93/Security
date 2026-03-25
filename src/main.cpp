#include <sodium.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "encrypt_decrypt.hpp"

int main(int argc, char* argv[]) {
  try {
    if (argc != 3) {
      throw std::invalid_argument("Was expecting 2 arguments, got: " +
                                  std::to_string(argc - 1));
    }

    if (sodium_init() < 0) {
      throw std::runtime_error("Failed to initialize libsodium library");
    }

    std::vector<std::string> args(argv, argv + argc);
    const std::string& task{args[1]};
    const std::string& file_name{args[2]};

    if (task == "encrypt") {
      encrypt_file(file_name, get_password());
    } else if (task == "decrypt") {
      decrypt_file(file_name, get_password());
    } else {
      throw std::invalid_argument("Don't know how to do this: " + task);
    }

    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}

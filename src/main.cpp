#include <sodium.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "encrypt_decrypt.hpp"

int main(int argc, char* argv[]) {
  try {
    // Check if sodium is there
    if (sodium_init() < 0) {
      throw std::runtime_error("Failed to initialize libsodium library");
    }

    // Validate CLI arguments
    if (argc != 3) {
      throw std::invalid_argument("Was expecting 2 arguments, got: " +
                                  std::to_string(argc - 1));
    }

    run_task(Task{argv[1], argv[2]});

    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}

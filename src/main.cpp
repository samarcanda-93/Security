#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "decrypt.hpp"
#include "encrypt.hpp"

auto main(int argc, char* argv[]) -> int {
  try {
    if (argc != 3) {
      throw std::invalid_argument("Was expecting 2 arguments, got: " +
                                  std::to_string(argc - 1));
    }

    std::vector<std::string> args(argv, argv + argc);
    const std::string& task{args[1]};
    const std::string& file_name{args[2]};

    if (task == "encrypt") {
      encrypt_file(file_name);
    } else if (task == "decrypt") {
      decrypt_file(file_name);
    } else {
      throw std::invalid_argument("Don't know how to do this: " + task);
    }

    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}

#include "encrypt_decrypt.hpp"

#include <termios.h>
#include <unistd.h>

#include <cstddef>
#include <iostream>
#include <print>
#include <stdexcept>

namespace {
constexpr std::size_t MIN_LENGTH = 8;

class TerminalSettings {
 public:
  TerminalSettings() {
    // Store current terminal settings
    tcgetattr(STDIN_FILENO, &cur_settings_);
  }
  TerminalSettings(const TerminalSettings &) = delete;
  TerminalSettings(TerminalSettings &&) = delete;
  auto operator=(const TerminalSettings &) -> TerminalSettings & = delete;
  auto operator=(TerminalSettings &&) -> TerminalSettings & = delete;
  ~TerminalSettings() noexcept {
    // Use RAII to auto reset terminal settings if everything explodes
    tcsetattr(STDIN_FILENO, TCSANOW, &cur_settings_);
  };

  auto turn_off_echo() noexcept -> void {
    termios new_settings{cur_settings_};
    new_settings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
  }

 private:
  termios cur_settings_{};
};
}  // namespace

auto encrypt_file(std::string file_name, std::string password) -> void {
  std::print("Super safely encrypting {} here...", file_name);
}

auto decrypt_file(std::string file_name, std::string password) -> void {
  std::print("Super precise decrypting of {} here...", file_name);
}

auto get_password() -> std::string {
  std::println("Password must be lowercase alphabetic, minimum length is {}",
               MIN_LENGTH);
  std::println("Please insert password: ");

  TerminalSettings terminal_settings;
  terminal_settings.turn_off_echo();

  std::string password;
  int failed_attempts = 0;
  while (failed_attempts < 3) {
    std::cin >> password;

    bool valid_password = true;

    if (password.length() < MIN_LENGTH) {
      valid_password = false;
    }

    for (auto ch : password) {
      if (ch < 'a' || ch > 'z') {
        valid_password = false;
      }
    }

    if (valid_password) {
      std::print("Cool, thanks!");
      return password;
    }
    ++failed_attempts;
  }

  throw std::runtime_error("Too many attempts");
}

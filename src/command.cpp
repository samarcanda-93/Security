#include "command.hpp"

#include "encrypt_decrypt.hpp"

#include <memory>
#include <stdexcept>

auto Encrypt::execute() -> void { encrypt_file(task_, get_password()); }

auto Decrypt::execute() -> void { decrypt_file(task_, get_password()); }

auto make_command(const Task& task) -> std::unique_ptr<Command> {
  switch (task.command_type) {
    case CommandType::Encrypt:
      return std::make_unique<Encrypt>(task);
    case CommandType::Decrypt:
      return std::make_unique<Decrypt>(task);
  }

  throw std::invalid_argument("Unsupported command type");
}

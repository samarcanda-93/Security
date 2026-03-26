#include "command.hpp"

#include <memory>
#include <stdexcept>

#include "encrypt_decrypt.hpp"

auto Encrypt::execute() -> void { encrypt_file(task_); }

auto Decrypt::execute() -> void { decrypt_file(task_); }

auto make_command(const Task& task) -> std::unique_ptr<Command> {
  switch (task.command_type) {
    case TaskType::Encrypt:
      return std::make_unique<Encrypt>(task);
    case TaskType::Decrypt:
      return std::make_unique<Decrypt>(task);
  }

  throw std::invalid_argument("Unsupported command type");
}

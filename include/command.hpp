#pragma once

#include <sys/types.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

enum class CommandType : u_int8_t {
  Encrypt,
  Decrypt,
};

struct Task {
 public:
  Task(std::string command_name, std::string file_name)
      : file_name(std::move(file_name)) {
    if (command_name == "encrypt") {
      command_type = CommandType::Encrypt;
    } else if (command_name == "decrypt") {
      command_type = CommandType::Decrypt;
    } else {
      throw std::invalid_argument("Don't know this command: " + command_name);
    }
  }

  CommandType command_type;
  std::string file_name;
};

class Command {
 public:
  virtual auto execute() -> void = 0;

  Command() = default;
  Command(const Command&) = delete;
  Command(Command&&) = delete;
  auto operator=(const Command&) -> Command& = delete;
  auto operator=(Command&&) -> Command& = delete;
  virtual ~Command() = default;
};

class Encrypt final : public Command {
 public:
  auto execute() -> void override;

  Encrypt(Task task) : task_(std::move(task)) {}

 private:
  Task task_;
};

class Decrypt final : public Command {
 public:
  auto execute() -> void override;

  Decrypt(Task task) : task_(std::move(task)) {}

 private:
  Task task_;
};

auto make_command(const Task& task) -> std::unique_ptr<Command>;

#pragma once

#include <string>

#include "command.hpp"

auto decrypt_file(const Task& task, const std::string& password) -> void;
auto encrypt_file(const Task& task, const std::string& password) -> void;

auto get_password() -> std::string;
auto is_valid_password(const std::string& password) -> bool;

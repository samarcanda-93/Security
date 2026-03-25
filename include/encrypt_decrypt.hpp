#pragma once

#include "command.hpp"

#include <string>

auto decrypt_file(const Task& task, std::string password) -> void;
auto encrypt_file(const Task& task, std::string password) -> void;

auto get_password() -> std::string;
auto is_valid_password(const std::string& password) -> bool;

#pragma once

#include <string>

auto decrypt_file(std::string file_name, std::string password) -> void;
auto encrypt_file(std::string file_name, std::string password) -> void;

auto get_password() -> std::string;
auto is_valid_password(const std::string& password) -> bool;

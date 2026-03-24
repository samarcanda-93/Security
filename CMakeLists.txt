cmake_minimum_required(VERSION 3.28)
project(Security LANGUAGES CXX)

# --- STANDARD C++23 ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB SOURCES CONFIGURE_DEPENDS "src/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE include/)

# option(BUILD_TESTS "Build tests" OFF)

# if(BUILD_TESTS) add_executable(tests tests/test_security.cpp
# src/evaluator.cpp) target_include_directories(tests PRIVATE include/) endif()

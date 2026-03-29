cmake_minimum_required(VERSION 3.28)
project(Security LANGUAGES CXX)

# --- STANDARD C++23 ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_library(SODIUM_LIB sodium REQUIRED)

add_executable(${PROJECT_NAME} src/main.cpp src/credentials.cpp
                               src/encrypt_decrypt.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE include/)
target_link_libraries(${PROJECT_NAME} PRIVATE ${SODIUM_LIB})

option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
  enable_testing()
  find_package(GTest REQUIRED)
  add_executable(tests tests/test_security.cpp src/encrypt_decrypt.cpp
                       src/credentials.cpp)
  target_include_directories(tests PRIVATE include/)
  target_link_libraries(tests PRIVATE GTest::gtest_main ${SODIUM_LIB})
  include(GoogleTest)
  gtest_discover_tests(tests)
endif()

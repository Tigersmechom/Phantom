cmake_minimum_required(VERSION 3.21)
project(phantom_backend VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(phantom-backend src/main.cpp)
target_compile_definitions(phantom-backend PRIVATE
  PHANTOM_BACKEND_VERSION="${PROJECT_VERSION}")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(phantom-backend PRIVATE -Wall -Wextra -Wpedantic)
endif()

# This fixture tests an installed rr manually. It is not a debugger engine.
add_executable(phantom-rr-fixture EXCLUDE_FROM_ALL fixtures/rr-smoke.cpp)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(phantom-rr-fixture PRIVATE -g -O0 -fno-omit-frame-pointer)
endif()

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
  add_test(NAME scaffold-cli
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.py"
      "$<TARGET_FILE:phantom-backend>" "${PROJECT_VERSION}")
  set_tests_properties(scaffold-cli PROPERTIES TIMEOUT 15)
endif()

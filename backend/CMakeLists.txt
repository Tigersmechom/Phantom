cmake_minimum_required(VERSION 3.21)
project(phantom_backend VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)
find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

add_library(phantom-core STATIC
  src/gdb.cpp
  src/mi.cpp
  src/process.cpp
  src/service.cpp
  src/sha256.cpp
  src/validation.cpp
)
target_include_directories(phantom-core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
)
target_link_libraries(phantom-core PUBLIC Threads::Threads)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(phantom-core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(phantom-backend src/main.cpp)
target_link_libraries(phantom-backend PRIVATE phantom-core)
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

add_executable(phantom-sha256-test tests/sha256_test.cpp)
target_link_libraries(phantom-sha256-test PRIVATE phantom-core)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(phantom-sha256-test PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(phantom-process-mi-test tests/process_mi_test.cpp)
target_link_libraries(phantom-process-mi-test PRIVATE phantom-core)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(phantom-process-mi-test PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(phantom-validation-test tests/validation_test.cpp)
target_link_libraries(phantom-validation-test PRIVATE phantom-core)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(phantom-validation-test PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if(BUILD_TESTING)
  add_test(NAME scaffold-cli
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.py"
      "$<TARGET_FILE:phantom-backend>" "${PROJECT_VERSION}")
  set_tests_properties(scaffold-cli PROPERTIES TIMEOUT 15)
  add_test(NAME sha256
    COMMAND "$<TARGET_FILE:phantom-sha256-test>")
  set_tests_properties(sha256 PROPERTIES TIMEOUT 15)
  add_test(NAME process-mi
    COMMAND "$<TARGET_FILE:phantom-process-mi-test>")
  set_tests_properties(process-mi PROPERTIES TIMEOUT 30)
  add_test(NAME validation
    COMMAND "$<TARGET_FILE:phantom-validation-test>")
  set_tests_properties(validation PROPERTIES TIMEOUT 15)
  add_test(NAME service-integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/service_integration.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(service-integration PROPERTIES TIMEOUT 60)
  add_test(NAME transport
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/transport_test.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(transport PROPERTIES TIMEOUT 60)
endif()

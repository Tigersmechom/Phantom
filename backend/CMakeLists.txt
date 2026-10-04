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
  src/memory_map.cpp
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

add_executable(phantom-io-wrapper src/io_wrapper.cpp)
add_dependencies(phantom-backend phantom-io-wrapper)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(phantom-io-wrapper PRIVATE -Wall -Wextra -Wpedantic)
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
  add_executable(phantom-memory-map-test tests/memory_map_test.cpp)
  target_link_libraries(phantom-memory-map-test PRIVATE phantom-core)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(phantom-memory-map-test PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  add_test(NAME memory-map COMMAND "$<TARGET_FILE:phantom-memory-map-test>")
  set_tests_properties(memory-map PROPERTIES TIMEOUT 15)
  add_test(NAME memory-gateway-integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/memory_gateway_integration.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(memory-gateway-integration PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
  add_executable(phantom-gdb-test-fixture fixtures/gdb-test.cpp)
  target_compile_options(phantom-gdb-test-fixture PRIVATE -g -O0 -fno-omit-frame-pointer)
  # This target is the inferior, not the code under test. LeakSanitizer cannot
  # run under GDB/ptrace and would change its exit code and captured stderr.
  # Keep instrumentation on the engine, service, wrapper and test executable.
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(phantom-gdb-test-fixture PRIVATE -fno-sanitize=all)
    target_link_options(phantom-gdb-test-fixture PRIVATE -fno-sanitize=all)
  endif()
  add_executable(phantom-gdb-engine-test tests/gdb_engine_test.cpp)
  target_link_libraries(phantom-gdb-engine-test PRIVATE phantom-core)
  target_compile_options(phantom-gdb-engine-test PRIVATE -Wall -Wextra -Wpedantic)
  add_dependencies(phantom-gdb-engine-test phantom-gdb-test-fixture phantom-io-wrapper)
  add_test(NAME gdb-engine COMMAND "$<TARGET_FILE:phantom-gdb-engine-test>"
    "$<TARGET_FILE:phantom-gdb-test-fixture>" "$<TARGET_FILE:phantom-io-wrapper>"
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/gdb-test.cpp")
  set_tests_properties(gdb-engine PROPERTIES TIMEOUT 30)
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
  add_test(NAME io-integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/io_integration.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(io-integration PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
  add_test(NAME interactive-input-integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/interactive_input_integration.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(interactive-input-integration PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
  add_test(NAME lifecycle-integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/lifecycle_integration.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(lifecycle-integration PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
  find_program(PHANTOM_TYPESCRIPT_EXECUTABLE NAMES tsc
    HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../node_modules/.bin")
  if(PHANTOM_TYPESCRIPT_EXECUTABLE)
    add_test(NAME frontend-contract
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/frontend_contract_test.py"
        "$<TARGET_FILE:phantom-backend>" --tsc "${PHANTOM_TYPESCRIPT_EXECUTABLE}")
    set_tests_properties(frontend-contract PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
  endif()
  add_test(NAME transport
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/transport_test.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(transport PROPERTIES TIMEOUT 60)
endif()

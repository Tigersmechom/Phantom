cmake_minimum_required(VERSION 3.21)
project(phantom_backend VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)
find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

add_library(phantom-core STATIC
  src/service_symbols.cpp
  src/service_layout.cpp
  src/elf_symbols.cpp
  src/service_recording.cpp
  src/service_probe.cpp
  src/service_modules.cpp
  src/recorder_probe.cpp
  src/module_map.cpp
  src/output_journal.cpp
  src/elf.cpp
  src/process_inspection.cpp
  src/service_inspection.cpp
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
add_executable(phantom-recorder-probe fixtures/recorder-probe.cpp)
target_compile_options(phantom-recorder-probe PRIVATE -g -O0 -fno-omit-frame-pointer -fno-sanitize=all)
target_link_options(phantom-recorder-probe PRIVATE -fno-sanitize=all)
add_dependencies(phantom-backend phantom-io-wrapper phantom-recorder-probe)
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
  foreach(symbol_fixture IN ITEMS phantom-elf-symbols-library phantom-elf-symbols-stripped-library)
    add_library(${symbol_fixture} SHARED fixtures/elf-symbols.cpp)
    target_compile_options(${symbol_fixture} PRIVATE -g -fno-sanitize=all)
    target_link_options(${symbol_fixture} PRIVATE -fno-sanitize=all)
  endforeach()
  target_link_options(phantom-elf-symbols-stripped-library PRIVATE -s)
  add_library(phantom-module-symbols-library SHARED fixtures/module-symbols-library.cpp)
  target_compile_options(phantom-module-symbols-library PRIVATE -g -fno-sanitize=all)
  target_link_options(phantom-module-symbols-library PRIVATE -fno-sanitize=all)
  add_library(phantom-module-map-library SHARED fixtures/module-map-library.cpp)
  target_compile_options(phantom-module-map-library PRIVATE -g -fno-sanitize=all)
  target_link_options(phantom-module-map-library PRIVATE -fno-sanitize=all)
  foreach(module IN ITEMS elf elf-symbols module-symbols process-inspection output-journal recorder-probe module-map)
    string(REPLACE "-" "_" test_file "${module}")
    add_executable(phantom-${module}-test tests/${test_file}_test.cpp)
    target_link_libraries(phantom-${module}-test PRIVATE phantom-core)
    if(module STREQUAL "elf-symbols")
      add_dependencies(phantom-${module}-test phantom-elf-symbols-library phantom-elf-symbols-stripped-library)
      add_test(NAME ${module} COMMAND "$<TARGET_FILE:phantom-${module}-test>"
        "$<TARGET_FILE:phantom-elf-symbols-library>" "$<TARGET_FILE:phantom-elf-symbols-stripped-library>")
    elseif(module STREQUAL "module-symbols")
      add_dependencies(phantom-${module}-test phantom-module-symbols-library)
      target_link_libraries(phantom-${module}-test PRIVATE ${CMAKE_DL_LIBS})
      add_test(NAME ${module} COMMAND "$<TARGET_FILE:phantom-${module}-test>" "$<TARGET_FILE:phantom-module-symbols-library>")
    elseif(module STREQUAL "recorder-probe")
      add_dependencies(phantom-${module}-test phantom-recorder-probe)
      add_test(NAME ${module} COMMAND "$<TARGET_FILE:phantom-${module}-test>" "$<TARGET_FILE:phantom-recorder-probe>")
    elseif(module STREQUAL "module-map")
      add_dependencies(phantom-${module}-test phantom-module-map-library)
      target_link_libraries(phantom-${module}-test PRIVATE ${CMAKE_DL_LIBS})
      add_test(NAME ${module} COMMAND "$<TARGET_FILE:phantom-${module}-test>" "$<TARGET_FILE:phantom-module-map-library>")
    else()
      add_test(NAME ${module} COMMAND "$<TARGET_FILE:phantom-${module}-test>")
    endif()
    set_tests_properties(${module} PROPERTIES TIMEOUT 15)
  endforeach()
  foreach(integration IN ITEMS address_profile advanced_gateway trace_failure output_journal recorder_probe recording layout)
    add_test(NAME ${integration}-integration COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/${integration}_integration.py" "$<TARGET_FILE:phantom-backend>")
    set_tests_properties(${integration}-integration PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
  endforeach()
  add_test(NAME symbols-integration COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbols_integration.py" "$<TARGET_FILE:phantom-backend>" "$<TARGET_FILE:phantom-module-symbols-library>")
  set_tests_properties(symbols-integration PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
  add_test(NAME modules-integration COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/modules_integration.py" "$<TARGET_FILE:phantom-backend>" "$<TARGET_FILE:phantom-module-map-library>")
  set_tests_properties(modules-integration PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
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
  add_library(phantom-variable-layout-optimized OBJECT fixtures/variable-layout-optimized.cpp)
  target_compile_options(phantom-variable-layout-optimized PRIVATE -g -O2 -fno-omit-frame-pointer -fno-pie -fno-sanitize=all)
  add_executable(phantom-variable-layout-fixture fixtures/variable-layout.cpp $<TARGET_OBJECTS:phantom-variable-layout-optimized>)
  target_compile_options(phantom-variable-layout-fixture PRIVATE -g -O0 -fno-omit-frame-pointer -fno-pie -fno-sanitize=all)
  target_link_options(phantom-variable-layout-fixture PRIVATE -no-pie -fno-sanitize=all)
  add_executable(phantom-gdb-variable-layout-test tests/gdb_variable_layout_test.cpp)
  target_link_libraries(phantom-gdb-variable-layout-test PRIVATE phantom-core)
  add_dependencies(phantom-gdb-variable-layout-test phantom-variable-layout-fixture phantom-io-wrapper)
  add_test(NAME gdb-variable-layout COMMAND "$<TARGET_FILE:phantom-gdb-variable-layout-test>"
    "$<TARGET_FILE:phantom-variable-layout-fixture>" "$<TARGET_FILE:phantom-io-wrapper>"
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/variable-layout.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/variable-layout-optimized.cpp")
  set_tests_properties(gdb-variable-layout PROPERTIES TIMEOUT 90)
  add_executable(phantom-recording-test-fixture fixtures/recording-test.cpp)
  target_compile_options(phantom-recording-test-fixture PRIVATE -g -O0 -fno-omit-frame-pointer -fno-sanitize=all)
  target_link_options(phantom-recording-test-fixture PRIVATE -fno-sanitize=all)
  add_executable(phantom-gdb-recording-test tests/gdb_recording_test.cpp)
  target_link_libraries(phantom-gdb-recording-test PRIVATE phantom-core)
  add_dependencies(phantom-gdb-recording-test phantom-recording-test-fixture phantom-io-wrapper)
  add_test(NAME gdb-recording COMMAND "$<TARGET_FILE:phantom-gdb-recording-test>"
    "$<TARGET_FILE:phantom-recording-test-fixture>" "$<TARGET_FILE:phantom-io-wrapper>"
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/recording-test.cpp")
  set_tests_properties(gdb-recording PROPERTIES TIMEOUT 90)
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
    set_tests_properties(frontend-contract PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77)
  endif()
  add_test(NAME transport
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/transport_test.py"
      "$<TARGET_FILE:phantom-backend>")
  set_tests_properties(transport PROPERTIES TIMEOUT 60)
endif()

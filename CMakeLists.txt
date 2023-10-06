cmake_minimum_required(VERSION 3.14)
project(amzcrypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_compile_options(-Wall -Wextra -pedantic)

include_directories(include)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(SOURCES src/chunkyint.cpp)

# Test executables
add_executable(aes_appendix_c_test tests/aes_appendix_c_test.cpp)
add_executable(aes_benchmark tests/aes_benchmark.cpp)
add_executable(aes_constexpr_test tests/aes_constexpr_test.cpp)
add_executable(chunkyint_benchmark tests/chunkyint_benchmark.cpp ${SOURCES})
add_executable(chunkyint_mod_exp_test tests/chunkyint_mod_exp_test.cpp ${SOURCES})
add_executable(chunkyint_miller_rabin_test tests/chunkyint_miller_rabin_test.cpp ${SOURCES})
add_executable(sha1_benchmark tests/sha1_benchmark.cpp)
add_executable(sha1_compiletime_test tests/sha1_compiletime_test.cpp)
add_executable(sha1_smalltest tests/sha1_smalltest.cpp)

target_link_libraries(chunkyint_benchmark OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(chunkyint_mod_exp_test OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(chunkyint_miller_rabin_test OpenSSL::SSL OpenSSL::Crypto)

# Demo executables
add_executable(chunkyint_diffie_hellman demos/chunkyint_diffie_hellman.cpp ${SOURCES})
add_executable(chunkyint_rsa demos/chunkyint_rsa.cpp ${SOURCES})
add_executable(sha1_collision_attack demos/sha1_collision_attack.cpp)
add_executable(sha1_length_extension_attack demos/sha1_length_extension_attack.cpp)
add_executable(sha1_preimage_attack demos/sha1_preimage_attack.cpp)

target_link_libraries(chunkyint_diffie_hellman OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(chunkyint_rsa OpenSSL::SSL OpenSSL::Crypto)

# Add specific compile definitions or flags for certain targets
target_compile_definitions(aes_appendix_c_test PRIVATE AES_DEBUG)
set_target_properties(aes_benchmark PROPERTIES COMPILE_FLAGS "-pg")

file(GLOB ALL_BINARIES "${CMAKE_CURRENT_BINARY_DIR}/*")
add_custom_target(clean-custom
    COMMAND ${CMAKE_COMMAND} -E echo "Cleaning custom binaries..."
    COMMAND ${CMAKE_COMMAND} -E rm -f ${ALL_BINARIES}
    COMMENT "Cleaning up all binaries..."
)

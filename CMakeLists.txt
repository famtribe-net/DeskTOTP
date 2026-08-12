cmake_minimum_required(VERSION 3.16)

project(totp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSECRET REQUIRED IMPORTED_TARGET libsecret-1)
find_package(OpenSSL REQUIRED)

add_executable(totp
    src/main.cc
    src/cli.cc
    src/clipboard.cc
    src/keyring.cc
    src/terminal.cc
    src/totp.cc
    src/base32.cc
)

target_include_directories(totp PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_options(totp PRIVATE
    -Wall -Wextra -Wpedantic
    -Wconversion -Wshadow
)

target_link_libraries(totp PRIVATE
    PkgConfig::LIBSECRET
    OpenSSL::Crypto
)

install(TARGETS totp RUNTIME DESTINATION bin)

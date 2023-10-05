# amzcrypto
A C++ cryptographic library for educational purposes 

## :warning: **WARNING**
This library has been developed **solely for educational purposes** and contains known vulnerabilities and possibly undiscovered ones. It is **NOT** secure, has not been audited, and **SHOULD NOT** be used for any real-world cryptographic applications. Misuse will result in severe data breaches and other catastrophic consequences. Always rely on well-established and audited cryptographic libraries for any practical use, such as [OpenSSL's libcrypto](https://github.com/openssl/openssl/tree/master).

## Prerequisites
- C++ Compiler supporting C++23 or higher
- CMake version 3.14 or higher
- OpenSSL libraries (for certain features)

This repository comes with a Dev Container which provides all prerequisites.

## Compile Tests and Demos
To compile the test and demo programs, run the following commands:

    git clone https://github.com/alexmingzhang/amzcrypto.git
    mkdir build
    cd build
    cmake ..
    make

All binaries will be in `amzcrypto/bin`

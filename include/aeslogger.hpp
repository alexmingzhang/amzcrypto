#ifndef AMZCRYPTO_AESLOGGER_HPP
#define AMZCRYPTO_AESLOGGER_HPP
#pragma once

#include <iostream>

#ifdef AES_DEBUG
#define DEBUG_LOG(...) Logger::log(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif  // #ifdef AES_DEBUG

/**
 * @brief Toggle-able debug logger
 * @note To enable debug logging, add the flag "-DAES_DEBUG" to compilation
 */
class Logger {
public:
    template <typename... Args>
    static void log(Args... args) {
        internal_log(args...);
    }

private:
    template <typename First, typename... Rest>
    static void internal_log(const First& first, const Rest&... rest) {
        std::cout << first;
        internal_log(rest...);
    }

    static void internal_log() { std::cout << std::endl; }
};

#endif  // #ifndef AMZCRYPTO_AESLOGGER_HPP

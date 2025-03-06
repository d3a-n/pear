#include "../include/logger.h"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <mutex>
#include <cstdarg>

// C-compatible logging functions
extern "C" {
    void pear_log_debug(const char* format, ...) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        Logger::getInstance().debug(buffer);
    }

    void pear_log_info(const char* format, ...) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        Logger::getInstance().info(buffer);
    }

    void pear_log_step(const char* format, ...) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        Logger::getInstance().step(buffer);
    }

    void pear_log_warning(const char* format, ...) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        Logger::getInstance().warning(buffer);
    }

    void pear_log_error(const char* format, ...) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        Logger::getInstance().error(buffer);
    }
}

// Constructor
Logger::Logger() : currentLevel(PearLogLevel::INFO) {}

// Singleton instance
Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

// Set the minimum log level
void Logger::setLogLevel(PearLogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex);
    currentLevel = level;
}

// Log methods
void Logger::debug(const std::string& message) {
    if (currentLevel <= PearLogLevel::DEBUG) {
        log(PearLogLevel::DEBUG, message);
    }
}

void Logger::info(const std::string& message) {
    if (currentLevel <= PearLogLevel::INFO) {
        log(PearLogLevel::INFO, message);
    }
}

void Logger::step(const std::string& message) {
    if (currentLevel <= PearLogLevel::STEP) {
        log(PearLogLevel::STEP, message);
    }
}

void Logger::warning(const std::string& message) {
    if (currentLevel <= PearLogLevel::WARNING) {
        log(PearLogLevel::WARNING, message);
    }
}

void Logger::error(const std::string& message) {
    if (currentLevel <= PearLogLevel::ERROR_LEVEL) {
        log(PearLogLevel::ERROR_LEVEL, message);
    }
}

// Internal log method
void Logger::log(PearLogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    // Get level string
    std::string levelStr;
    switch (level) {
        case PearLogLevel::DEBUG:
            levelStr = "DEBUG";
            break;
        case PearLogLevel::INFO:
            levelStr = "INFO";
            break;
        case PearLogLevel::STEP:
            levelStr = "STEP";
            break;
        case PearLogLevel::WARNING:
            levelStr = "WARNING";
            break;
        case PearLogLevel::ERROR_LEVEL:
            levelStr = "ERROR";
            break;
        default:
            levelStr = "UNKNOWN";
            break;
    }
    
    // Output to console
    std::ostream& out = (level >= PearLogLevel::WARNING) ? std::cerr : std::cout;
    out << "[" << ss.str() << "] [" << levelStr << "] " << message << std::endl;
}

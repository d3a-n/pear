#include "../include/logger.h"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <mutex>

// Constructor
Logger::Logger() : currentLevel(LogLevel::INFO) {}

// Singleton instance
Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

// Set the minimum log level
void Logger::setLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex);
    currentLevel = level;
}

// Log methods
void Logger::debug(const std::string& message) {
    if (currentLevel <= LogLevel::DEBUG) {
        log(LogLevel::DEBUG, message);
    }
}

void Logger::info(const std::string& message) {
    if (currentLevel <= LogLevel::INFO) {
        log(LogLevel::INFO, message);
    }
}

void Logger::step(const std::string& message) {
    if (currentLevel <= LogLevel::STEP) {
        log(LogLevel::STEP, message);
    }
}

void Logger::warning(const std::string& message) {
    if (currentLevel <= LogLevel::WARNING) {
        log(LogLevel::WARNING, message);
    }
}

void Logger::error(const std::string& message) {
    if (currentLevel <= LogLevel::ERROR_LEVEL) {
        log(LogLevel::ERROR_LEVEL, message);
    }
}

// Internal log method
void Logger::log(LogLevel level, const std::string& message) {
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
        case LogLevel::DEBUG:
            levelStr = "DEBUG";
            break;
        case LogLevel::INFO:
            levelStr = "INFO";
            break;
        case LogLevel::STEP:
            levelStr = "STEP";
            break;
        case LogLevel::WARNING:
            levelStr = "WARNING";
            break;
        case LogLevel::ERROR_LEVEL:
            levelStr = "ERROR";
            break;
        default:
            levelStr = "UNKNOWN";
            break;
    }
    
    // Output to console
    std::ostream& out = (level >= LogLevel::WARNING) ? std::cerr : std::cout;
    out << "[" << ss.str() << "] [" << levelStr << "] " << message << std::endl;
}

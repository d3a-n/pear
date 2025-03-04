#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <mutex>
#include <cstdio>  // For snprintf
#include <cstdarg> // For variadic functions

// Log levels
enum class LogLevel {
    DEBUG,
    INFO,
    STEP,
    WARNING,
    ERROR_LEVEL,  // Renamed from ERROR to avoid Windows macro clash
    NONE          // Used to disable logging
};

class Logger {
public:
    // Singleton instance
    static Logger& getInstance();

    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Set the minimum log level
    void setLogLevel(LogLevel level);

    // Log methods (string-based)
    void debug(const std::string& message);
    void info(const std::string& message);
    void step(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);

    // Log methods (format-based)
    template<typename... Args>
    void debug(const char* format, Args... args);

    template<typename... Args>
    void info(const char* format, Args... args);

    template<typename... Args>
    void step(const char* format, Args... args);

    template<typename... Args>
    void warning(const char* format, Args... args);

    template<typename... Args>
    void error(const char* format, Args... args);

private:
    // Private constructor for singleton
    Logger();
    
    // Current log level
    LogLevel currentLevel;
    
    // Mutex for thread safety
    std::mutex logMutex;
    
    // Internal log method
    void log(LogLevel level, const std::string& message);
    
    // Format a string with variable arguments
    template<typename... Args>
    std::string formatString(const char* format, Args... args);
};

// Convenience macros for logging
#define LOG_DEBUG(...)   Logger::getInstance().debug(__VA_ARGS__)
#define LOG_INFO(...)    Logger::getInstance().info(__VA_ARGS__)
#define LOG_STEP(...)    Logger::getInstance().step(__VA_ARGS__)
#define LOG_WARNING(...) Logger::getInstance().warning(__VA_ARGS__)
#define LOG_ERROR(...)   Logger::getInstance().error(__VA_ARGS__)

// Template implementations
template<typename... Args>
void Logger::debug(const char* format, Args... args) {
    if (currentLevel <= LogLevel::DEBUG) {
        log(LogLevel::DEBUG, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::info(const char* format, Args... args) {
    if (currentLevel <= LogLevel::INFO) {
        log(LogLevel::INFO, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::step(const char* format, Args... args) {
    if (currentLevel <= LogLevel::STEP) {
        log(LogLevel::STEP, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::warning(const char* format, Args... args) {
    if (currentLevel <= LogLevel::WARNING) {
        log(LogLevel::WARNING, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::error(const char* format, Args... args) {
    if (currentLevel <= LogLevel::ERROR_LEVEL) {
        log(LogLevel::ERROR_LEVEL, formatString(format, args...));
    }
}

template<typename... Args>
std::string Logger::formatString(const char* format, Args... args) {
    // Temporarily suppress -Wformat-security warnings for variadic snprintf
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wformat-security"
    int size = std::snprintf(nullptr, 0, format, args...);
    #pragma GCC diagnostic pop

    if (size <= 0) {
        return "Error formatting log message";
    }
    
    // Allocate buffer (including null terminator)
    std::string buffer(size + 1, '\0');
    
    // Suppress -Wformat-security again for the actual write
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wformat-security"
    std::snprintf(&buffer[0], size + 1, format, args...);
    #pragma GCC diagnostic pop

    // Resize to discard the trailing null
    buffer.resize(size);
    
    return buffer;
}

#endif // LOGGER_H

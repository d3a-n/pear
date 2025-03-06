#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <mutex>
#include <cstdio>  // For snprintf
#include <cstdarg> // For variadic functions

// C compatibility
#ifdef __cplusplus
extern "C" {
#endif

// C-compatible logging functions
void pear_log_debug(const char* format, ...);
void pear_log_info(const char* format, ...);
void pear_log_step(const char* format, ...);
void pear_log_warning(const char* format, ...);
void pear_log_error(const char* format, ...);

#ifdef __cplusplus
}
#endif

// Log levels
enum class PearLogLevel {
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
    void setLogLevel(PearLogLevel level);

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
    PearLogLevel currentLevel;
    
    // Mutex for thread safety
    std::mutex logMutex;
    
    // Internal log method
    void log(PearLogLevel level, const std::string& message);
    
    // Format a string with variable arguments
    template<typename... Args>
    std::string formatString(const char* format, Args... args);
};

// Convenience macros for logging
#ifdef __cplusplus
#define PEAR_LOG_DEBUG(...)   Logger::getInstance().debug(__VA_ARGS__)
#define PEAR_LOG_INFO(...)    Logger::getInstance().info(__VA_ARGS__)
#define PEAR_LOG_STEP(...)    Logger::getInstance().step(__VA_ARGS__)
#define PEAR_LOG_WARNING(...) Logger::getInstance().warning(__VA_ARGS__)
#define PEAR_LOG_ERROR(...)   Logger::getInstance().error(__VA_ARGS__)
#else
#define PEAR_LOG_DEBUG(...)   pear_log_debug(__VA_ARGS__)
#define PEAR_LOG_INFO(...)    pear_log_info(__VA_ARGS__)
#define PEAR_LOG_STEP(...)    pear_log_step(__VA_ARGS__)
#define PEAR_LOG_WARNING(...) pear_log_warning(__VA_ARGS__)
#define PEAR_LOG_ERROR(...)   pear_log_error(__VA_ARGS__)
#endif

// Template implementations
template<typename... Args>
void Logger::debug(const char* format, Args... args) {
    if (currentLevel <= PearLogLevel::DEBUG) {
        log(PearLogLevel::DEBUG, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::info(const char* format, Args... args) {
    if (currentLevel <= PearLogLevel::INFO) {
        log(PearLogLevel::INFO, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::step(const char* format, Args... args) {
    if (currentLevel <= PearLogLevel::STEP) {
        log(PearLogLevel::STEP, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::warning(const char* format, Args... args) {
    if (currentLevel <= PearLogLevel::WARNING) {
        log(PearLogLevel::WARNING, formatString(format, args...));
    }
}

template<typename... Args>
void Logger::error(const char* format, Args... args) {
    if (currentLevel <= PearLogLevel::ERROR_LEVEL) {
        log(PearLogLevel::ERROR_LEVEL, formatString(format, args...));
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

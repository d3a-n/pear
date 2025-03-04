#ifndef UTILS_H
#define UTILS_H

#ifdef _WIN32
  #define PATH_SEPARATOR "\\"
#else
  #define PATH_SEPARATOR "/"
#endif

#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <functional>

// String utilities
namespace StringUtils {
    // Split a string by delimiter
    std::vector<std::string> split(const std::string& str, char delimiter);
    
    // Trim whitespace from beginning and end of string
    std::string trim(const std::string& str);
    
    // Convert string to lowercase
    std::string toLower(const std::string& str);
    
    // Convert string to uppercase
    std::string toUpper(const std::string& str);
    
    // Check if string starts with prefix
    bool startsWith(const std::string& str, const std::string& prefix);
    
    // Check if string ends with suffix
    bool endsWith(const std::string& str, const std::string& suffix);
    
    // Replace all occurrences of a substring
    std::string replaceAll(const std::string& str, const std::string& from, const std::string& to);
    
    // Format a string with printf-style arguments
    template<typename... Args>
    std::string format(const char* fmt, Args... args);
}

// Time utilities
namespace TimeUtils {
    // Get current timestamp in milliseconds
    uint64_t getCurrentTimeMs();
    
    // Get current timestamp in seconds
    uint64_t getCurrentTimeSec();
    
    // Format timestamp as string
    std::string formatTimestamp(uint64_t timestamp);
    
    // Sleep for milliseconds
    void sleepMs(uint32_t milliseconds);
    
    // Get random delay between min and max milliseconds
    uint32_t getRandomDelay(uint32_t minMs, uint32_t maxMs);
}

// Random utilities
namespace RandomUtils {
    // Initialize random number generator
    void initialize();
    
    // Get random bytes
    void getRandomBytes(unsigned char* buffer, size_t length);
    
    // Get random integer in range [min, max]
    int getRandomInt(int min, int max);
    
    // Get random double in range [min, max]
    double getRandomDouble(double min, double max);
    
    // Get random string of specified length
    std::string getRandomString(size_t length);
    
    // Get random alphanumeric string of specified length
    std::string getRandomAlphanumeric(size_t length);
}

// System utilities
namespace SystemUtils {
    // Check if file exists
    bool fileExists(const std::string& path);
    
    // Get home directory
    std::string getHomeDirectory();
    
    // Get temporary directory
    std::string getTempDirectory();
    
    // Get executable directory
    std::string getExecutableDirectory();
    
    // Create directory if it doesn't exist
    bool createDirectory(const std::string& path);
    
    // Delete file securely (overwrite with random data before deleting)
    bool secureDeleteFile(const std::string& path);
    
    // Get system information
    std::string getSystemInfo();
}

#endif // UTILS_H

#include "../include/utils.h"
#include "../include/logger.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <shlobj.h>
#define PATH_SEPARATOR "\\"
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <limits.h>  // For PATH_MAX
#include <mach-o/dyld.h> // For _NSGetExecutablePath
#include <stdlib.h>  // For realpath
#define PATH_SEPARATOR "/"
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <limits.h>  // For PATH_MAX
#define PATH_SEPARATOR "/"
#endif

// String utilities implementation
namespace StringUtils {
    
    std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(str);
        
        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(token);
        }
        
        return tokens;
    }
    
    std::string trim(const std::string& str) {
        auto start = std::find_if_not(str.begin(), str.end(), [](unsigned char c) {
            return std::isspace(c);
        });
        
        auto end = std::find_if_not(str.rbegin(), str.rend(), [](unsigned char c) {
            return std::isspace(c);
        }).base();
        
        return (start < end) ? std::string(start, end) : std::string();
    }
    
    std::string toLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
            return std::tolower(c);
        });
        return result;
    }
    
    std::string toUpper(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
            return std::toupper(c);
        });
        return result;
    }
    
    bool startsWith(const std::string& str, const std::string& prefix) {
        return str.size() >= prefix.size() && 
               str.compare(0, prefix.size(), prefix) == 0;
    }
    
    bool endsWith(const std::string& str, const std::string& suffix) {
        return str.size() >= suffix.size() && 
               str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    
    std::string replaceAll(const std::string& str, const std::string& from, const std::string& to) {
        std::string result = str;
        size_t pos = 0;
        
        while ((pos = result.find(from, pos)) != std::string::npos) {
            result.replace(pos, from.length(), to);
            pos += to.length();
        }
        
        return result;
    }
    
    // Template specialization for format is in the header
}

// Time utilities implementation
namespace TimeUtils {
    
    uint64_t getCurrentTimeMs() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    }
    
    uint64_t getCurrentTimeSec() {
        return getCurrentTimeMs() / 1000;
    }
    
    std::string formatTimestamp(uint64_t timestamp) {
        time_t time = timestamp / 1000;
        struct tm* timeinfo = localtime(&time);
        
        char buffer[80];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        std::stringstream ss;
        ss << buffer << "." << std::setfill('0') << std::setw(3) << (timestamp % 1000);
        
        return ss.str();
    }
    
    void sleepMs(uint32_t milliseconds) {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }
    
    uint32_t getRandomDelay(uint32_t minMs, uint32_t maxMs) {
        return RandomUtils::getRandomInt(minMs, maxMs);
    }
}

// Random utilities implementation
namespace RandomUtils {
    
    static std::mt19937 rng;
    static bool initialized = false;
    
    void initialize() {
        if (!initialized) {
            // Seed with high-resolution clock and random device
            std::random_device rd;
            auto seed = rd() ^ static_cast<unsigned int>(
                std::chrono::high_resolution_clock::now().time_since_epoch().count());
            
            rng.seed(seed);
            initialized = true;
            
            PEAR_LOG_DEBUG("Random number generator initialized");
        }
    }
    
    void getRandomBytes(unsigned char* buffer, size_t length) {
        if (!initialized) {
            initialize();
        }
        
        std::uniform_int_distribution<int> dist(0, 255);
        
        for (size_t i = 0; i < length; ++i) {
            buffer[i] = static_cast<unsigned char>(dist(rng));
        }
    }
    
    int getRandomInt(int min, int max) {
        if (!initialized) {
            initialize();
        }
        
        std::uniform_int_distribution<int> dist(min, max);
        return dist(rng);
    }
    
    double getRandomDouble(double min, double max) {
        if (!initialized) {
            initialize();
        }
        
        std::uniform_real_distribution<double> dist(min, max);
        return dist(rng);
    }
    
    std::string getRandomString(size_t length) {
        if (!initialized) {
            initialize();
        }
        
        const char charset[] = "0123456789"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "!@#$%^&*()_+=-[]{}|;:,.<>?";
        
        std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
        
        std::string result;
        result.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            result += charset[dist(rng)];
        }
        
        return result;
    }
    
    std::string getRandomAlphanumeric(size_t length) {
        if (!initialized) {
            initialize();
        }
        
        const char charset[] = "0123456789"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz";
        
        std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
        
        std::string result;
        result.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            result += charset[dist(rng)];
        }
        
        return result;
    }
}

// System utilities implementation
namespace SystemUtils {
    
    bool fileExists(const std::string& path) {
        std::ifstream file(path);
        return file.good();
    }
    
    std::string getHomeDirectory() {
#ifdef _WIN32
        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
            return std::string(path);
        }
        return "";
#else
        const char* home = getenv("HOME");
        if (home) {
            return std::string(home);
        }
        
        struct passwd* pwd = getpwuid(getuid());
        if (pwd) {
            return std::string(pwd->pw_dir);
        }
        
        return "";
#endif
    }
    
    std::string getTempDirectory() {
#ifdef _WIN32
        char path[MAX_PATH];
        DWORD length = GetTempPathA(MAX_PATH, path);
        if (length > 0) {
            return std::string(path);
        }
        return "";
#else
        const char* temp = getenv("TMPDIR");
        if (temp) {
            return std::string(temp);
        }
        return "/tmp";
#endif
    }
    
    std::string getExecutableDirectory() {
#ifdef _WIN32
        // Windows implementation
        char path[MAX_PATH];
        if (GetModuleFileNameA(NULL, path, MAX_PATH) > 0) {
            std::string exePath(path);
            size_t pos = exePath.find_last_of(PATH_SEPARATOR);
            if (pos != std::string::npos) {
                return exePath.substr(0, pos);
            }
        }
        return "";
#elif defined(__APPLE__)
        // macOS implementation
        char path[PATH_MAX];
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0) {
            // _NSGetExecutablePath returns a path with symlinks
            // Use realpath to resolve them
            char real_path[PATH_MAX];
            if (realpath(path, real_path) != NULL) {
                std::string exePath(real_path);
                size_t pos = exePath.find_last_of(PATH_SEPARATOR);
                if (pos != std::string::npos) {
                    return exePath.substr(0, pos);
                }
            }
        }
        return "";
#elif defined(__linux__)
        // Linux implementation
        char path[PATH_MAX];
        ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
        if (count != -1) {
            std::string exePath(path, count);
            size_t pos = exePath.find_last_of(PATH_SEPARATOR);
            if (pos != std::string::npos) {
                return exePath.substr(0, pos);
            }
        }
        return "";
#else
        // Fallback for other platforms
        return "";
#endif
    }
    
    bool createDirectory(const std::string& path) {
#ifdef _WIN32
        return _mkdir(path.c_str()) == 0 || errno == EEXIST;
#else
        return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
#endif
    }
    
    bool secureDeleteFile(const std::string& path) {
        // Open the file for binary writing
        std::ofstream file(path, std::ios::binary | std::ios::out);
        if (!file) {
            PEAR_LOG_ERROR("Failed to open file for secure deletion: %s", path.c_str());
            return false;
        }
        
        // Get file size
        file.seekp(0, std::ios::end);
        std::streampos fileSize = file.tellp();
        file.seekp(0, std::ios::beg);
        
        // Allocate buffer for random data
        const size_t bufferSize = 4096;
        unsigned char buffer[bufferSize];
        
        // Overwrite with random data (3 passes)
        for (int pass = 0; pass < 3; ++pass) {
            PEAR_LOG_DEBUG("Secure delete pass %d for file: %s", pass + 1, path.c_str());
            
            file.seekp(0, std::ios::beg);
            std::streampos remaining = fileSize;
            
            while (remaining > 0) {
                size_t bytesToWrite = std::min(static_cast<size_t>(remaining), bufferSize);
                
                // Fill buffer with random data
                RandomUtils::getRandomBytes(buffer, bytesToWrite);
                
                // Write to file
                file.write(reinterpret_cast<char*>(buffer), bytesToWrite);
                
                if (!file) {
                    PEAR_LOG_ERROR("Failed to write during secure deletion: %s", path.c_str());
                    file.close();
                    return false;
                }
                
                remaining -= bytesToWrite;
            }
            
            // Flush to ensure data is written
            file.flush();
        }
        
        // Close the file
        file.close();
        
        // Delete the file
        if (std::remove(path.c_str()) != 0) {
            PEAR_LOG_ERROR("Failed to remove file after secure deletion: %s", path.c_str());
            return false;
        }
        
        PEAR_LOG_DEBUG("File securely deleted: %s", path.c_str());
        return true;
    }
    
    std::string getSystemInfo() {
        std::stringstream ss;
        
#ifdef _WIN32
        ss << "Windows";
        OSVERSIONINFOA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
        
        #pragma warning(disable: 4996)
        if (GetVersionExA(&osvi)) {
            ss << " " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
        }
        #pragma warning(default: 4996)
#elif defined(__APPLE__)
        ss << "macOS";
#elif defined(__linux__)
        ss << "Linux";
#else
        ss << "Unknown OS";
#endif
        
        ss << " (" << (sizeof(void*) * 8) << "-bit)";
        
        return ss.str();
    }
}

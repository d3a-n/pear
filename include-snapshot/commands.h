#ifndef COMMANDS_H
#define COMMANDS_H

#include <string>
#include <vector>
#include <functional>
#include <map>

#include "chat.h"

// Command handler function type
using CommandHandler = std::function<bool(const std::vector<std::string>&, ChatSession*)>;

// Command class
class CommandProcessor {
public:
    // Singleton instance
    static CommandProcessor& getInstance();

    // Delete copy constructor and assignment operator
    CommandProcessor(const CommandProcessor&) = delete;
    CommandProcessor& operator=(const CommandProcessor&) = delete;

    // Process a command string
    bool processCommand(const std::string& commandStr, ChatSession* session);

    // Register a new command
    void registerCommand(const std::string& name, 
                         const std::string& description,
                         CommandHandler handler);

    // Get help text for all commands
    std::string getHelpText() const;

private:
    // Private constructor for singleton
    CommandProcessor();

    // Command information
    struct CommandInfo {
        std::string name;
        std::string description;
        CommandHandler handler;
    };

    // Command map
    std::map<std::string, CommandInfo> commands;

    // Parse command string into command and arguments
    std::pair<std::string, std::vector<std::string>> parseCommand(const std::string& commandStr);

    // Register built-in commands
    void registerBuiltInCommands();

    // Built-in command handlers
    static bool helpCommand(const std::vector<std::string>& args, ChatSession* session);
    static bool clearCommand(const std::vector<std::string>& args, ChatSession* session);
    static bool pingCommand(const std::vector<std::string>& args, ChatSession* session);
    static bool disconnectCommand(const std::vector<std::string>& args, ChatSession* session);
    static bool refreshCommand(const std::vector<std::string>& args, ChatSession* session);
};

// Convenience function to check if a string is a command
bool isCommand(const std::string& text);

#endif // COMMANDS_H

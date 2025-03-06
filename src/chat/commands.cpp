#include "../../include/commands.h"
#include "../../include/logger.h"
#include "../../include/utils.h"
#include <algorithm>
#include <sstream>
#include <iostream>

// Singleton instance
CommandProcessor& CommandProcessor::getInstance() {
    static CommandProcessor instance;
    return instance;
}

// Constructor
CommandProcessor::CommandProcessor() {
    registerBuiltInCommands();
}

// Process a command string
bool CommandProcessor::processCommand(const std::string& commandStr, ChatSession* session) {
    if (!isCommand(commandStr)) {
        return false;
    }
    
    // Parse the command
    auto [cmd, args] = parseCommand(commandStr);
    
    // Look up the command
    auto it = commands.find(cmd);
    if (it == commands.end()) {
        PEAR_LOG_WARNING("Unknown command: %s", cmd.c_str());
        return false;
    }
    
    // Execute the command
    PEAR_LOG_DEBUG("Executing command: %s", cmd.c_str());
    return it->second.handler(args, session);
}

// Register a new command
void CommandProcessor::registerCommand(const std::string& name, 
                                      const std::string& description,
                                      CommandHandler handler) {
    CommandInfo info;
    info.name = name;
    info.description = description;
    info.handler = handler;
    
    commands[name] = info;
    PEAR_LOG_DEBUG("Registered command: %s", name.c_str());
}

// Get help text for all commands
std::string CommandProcessor::getHelpText() const {
    std::stringstream ss;
    ss << "Available commands:" << std::endl;
    
    for (const auto& pair : commands) {
        ss << "  /" << pair.first << " - " << pair.second.description << std::endl;
    }
    
    return ss.str();
}

// Parse command string into command and arguments
std::pair<std::string, std::vector<std::string>> CommandProcessor::parseCommand(const std::string& commandStr) {
    // Remove the leading slash
    std::string cmdStr = commandStr.substr(1);
    
    // Split into command and arguments
    std::vector<std::string> parts = StringUtils::split(cmdStr, ' ');
    
    if (parts.empty()) {
        return {"", {}};
    }
    
    std::string cmd = parts[0];
    std::vector<std::string> args(parts.begin() + 1, parts.end());
    
    return {cmd, args};
}

// Register built-in commands
void CommandProcessor::registerBuiltInCommands() {
    registerCommand("help", "Display available commands", helpCommand);
    registerCommand("cl", "Clear the terminal screen", clearCommand);
    registerCommand("pg", "Test connection latency", pingCommand);
    registerCommand("dc", "Disconnect from the current peer", disconnectCommand);
    registerCommand("rr", "Refresh I2P routes and tunnels", refreshCommand);
}

// Built-in command handlers
bool CommandProcessor::helpCommand(const std::vector<std::string>& args, ChatSession* session) {
    (void)args; // Unused parameter
    (void)session; // Unused parameter
    
    std::string helpText = CommandProcessor::getInstance().getHelpText();
    std::cout << helpText << std::endl;
    
    return true;
}

bool CommandProcessor::clearCommand(const std::vector<std::string>& args, ChatSession* session) {
    (void)args; // Unused parameter
    (void)session; // Unused parameter
    
    // Clear the terminal screen
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
    
    return true;
}

bool CommandProcessor::pingCommand(const std::vector<std::string>& args, ChatSession* session) {
    (void)args; // Unused parameter
    
    if (!session) {
        PEAR_LOG_ERROR("No active chat session");
        return false;
    }
    
    if (!session->isConnected()) {
        PEAR_LOG_ERROR("Not connected to a peer");
        return false;
    }
    
    // Send a ping
    return session->sendPing();
}

bool CommandProcessor::disconnectCommand(const std::vector<std::string>& args, ChatSession* session) {
    (void)args; // Unused parameter
    
    if (!session) {
        PEAR_LOG_ERROR("No active chat session");
        return false;
    }
    
    if (!session->isConnected()) {
        PEAR_LOG_ERROR("Not connected to a peer");
        return false;
    }
    
    // Disconnect
    session->disconnect();
    return true;
}

bool CommandProcessor::refreshCommand(const std::vector<std::string>& args, ChatSession* session) {
    (void)args; // Unused parameter
    
    if (!session) {
        PEAR_LOG_ERROR("No active chat session");
        return false;
    }
    
    if (!session->isConnected()) {
        PEAR_LOG_ERROR("Not connected to a peer");
        return false;
    }
    
    // Refresh tunnels
    return session->refreshTunnels();
}

// Check if a string is a command
bool isCommand(const std::string& text) {
    return !text.empty() && text[0] == '/';
}

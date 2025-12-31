#include "logger.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <filesystem>
#include <vector>

namespace Radix {

// Static member initialization
std::shared_ptr<spdlog::logger> Logger::blockchainLogger = nullptr;
std::shared_ptr<spdlog::logger> Logger::networkLogger = nullptr;
std::shared_ptr<spdlog::logger> Logger::apiLogger = nullptr;
std::shared_ptr<spdlog::logger> Logger::mainLogger = nullptr;
bool Logger::initialized = false;

void Logger::init(const std::string& logDir, const std::string& level) {
    if (initialized) {
        return; // Already initialized
    }

    // Create log directory if it doesn't exist
    std::filesystem::create_directories(logDir);

    // Parse log level
    spdlog::level::level_enum logLevel = parseLogLevel(level);

    // Set global pattern: [timestamp] [logger_name] [level] message
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] %v");

    // Create loggers
    blockchainLogger = createLogger("blockchain", logDir, logLevel);
    networkLogger = createLogger("network", logDir, logLevel);
    apiLogger = createLogger("api", logDir, logLevel);
    mainLogger = createLogger("main", logDir, logLevel);

    initialized = true;

    // Initial log message
    mainLogger->info("Radix Logger initialized - Log directory: {}, Level: {}", logDir, level);
}

std::shared_ptr<spdlog::logger> Logger::blockchain() {
    if (!initialized) {
        init(); // Initialize with defaults if not done yet
    }
    return blockchainLogger;
}

std::shared_ptr<spdlog::logger> Logger::network() {
    if (!initialized) {
        init();
    }
    return networkLogger;
}

std::shared_ptr<spdlog::logger> Logger::api() {
    if (!initialized) {
        init();
    }
    return apiLogger;
}

std::shared_ptr<spdlog::logger> Logger::main() {
    if (!initialized) {
        init();
    }
    return mainLogger;
}

void Logger::shutdown() {
    if (!initialized) {
        return;
    }

    // Flush all loggers
    if (blockchainLogger) blockchainLogger->flush();
    if (networkLogger) networkLogger->flush();
    if (apiLogger) apiLogger->flush();
    if (mainLogger) mainLogger->flush();

    // Shutdown spdlog
    spdlog::shutdown();
    initialized = false;
}

std::shared_ptr<spdlog::logger> Logger::createLogger(
    const std::string& name,
    const std::string& logDir,
    spdlog::level::level_enum level
) {
    // Create sinks
    std::vector<spdlog::sink_ptr> sinks;

    // Console sink (colored output)
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    consoleSink->set_level(level);
    sinks.push_back(consoleSink);

    // Rotating file sink (10MB max, 3 backup files)
    std::string logFilePath = logDir + "/" + name + ".log";
    auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        logFilePath,
        1024 * 1024 * 10,  // 10 MB
        3                  // 3 backup files
    );
    fileSink->set_level(level);
    sinks.push_back(fileSink);

    // Create logger with both sinks
    auto logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
    logger->set_level(level);
    logger->flush_on(spdlog::level::warn); // Auto-flush on warnings and errors

    // Register logger with spdlog
    spdlog::register_logger(logger);

    return logger;
}

spdlog::level::level_enum Logger::parseLogLevel(const std::string& level) {
    std::string lowerLevel = level;
    std::transform(lowerLevel.begin(), lowerLevel.end(), lowerLevel.begin(), ::tolower);

    if (lowerLevel == "trace") return spdlog::level::trace;
    if (lowerLevel == "debug") return spdlog::level::debug;
    if (lowerLevel == "info") return spdlog::level::info;
    if (lowerLevel == "warn" || lowerLevel == "warning") return spdlog::level::warn;
    if (lowerLevel == "error" || lowerLevel == "err") return spdlog::level::err;
    if (lowerLevel == "critical" || lowerLevel == "crit") return spdlog::level::critical;
    if (lowerLevel == "off") return spdlog::level::off;

    // Default to info if unrecognized
    return spdlog::level::info;
}

} // namespace Radix

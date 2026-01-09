#ifndef SOVERX_LOGGER_H
#define SOVERX_LOGGER_H

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <memory>
#include <string>

namespace Soverx {

/**
 * @brief Centralized logger utility using spdlog
 * 
 * Provides multiple named loggers for different components:
 * - blockchain: Core blockchain operations (mining, validation, UTXO)
 * - network: P2P networking, peer connections, message handling
 * - api: RPC server, authentication, rate limiting
 * - main: CLI operations, wallet actions, startup/shutdown
 * 
 * Each logger writes to both console (with colors) and rotating files.
 */
class Logger {
public:
    /**
     * @brief Initialize all loggers with specified directory and level
     * @param logDir Directory for log files (default: "./logs")
     * @param level Log level: "trace", "debug", "info", "warn", "error", "critical" (default: "info")
     */
    static void init(const std::string& logDir = "./logs", const std::string& level = "info");

    /**
     * @brief Get the blockchain logger
     */
    static std::shared_ptr<spdlog::logger> blockchain();

    /**
     * @brief Get the network logger
     */
    static std::shared_ptr<spdlog::logger> network();

    /**
     * @brief Get the api logger
     */
    static std::shared_ptr<spdlog::logger> api();

    /**
     * @brief Get the main logger
     */
    static std::shared_ptr<spdlog::logger> main();

    /**
     * @brief Shutdown all loggers and flush pending messages
     */
    static void shutdown();

private:
    static std::shared_ptr<spdlog::logger> blockchainLogger;
    static std::shared_ptr<spdlog::logger> networkLogger;
    static std::shared_ptr<spdlog::logger> apiLogger;
    static std::shared_ptr<spdlog::logger> mainLogger;
    static bool initialized;

    /**
     * @brief Create a logger with both console and file sinks
     */
    static std::shared_ptr<spdlog::logger> createLogger(
        const std::string& name,
        const std::string& logDir,
        spdlog::level::level_enum level
    );

    /**
     * @brief Parse log level string to spdlog level enum
     */
    static spdlog::level::level_enum parseLogLevel(const std::string& level);
};

// Convenience macros for cleaner code
#define LOG_TRACE(logger, ...) logger->trace(__VA_ARGS__)
#define LOG_DEBUG(logger, ...) logger->debug(__VA_ARGS__)
#define LOG_INFO(logger, ...) logger->info(__VA_ARGS__)
#define LOG_WARN(logger, ...) logger->warn(__VA_ARGS__)
#define LOG_ERROR(logger, ...) logger->error(__VA_ARGS__)
#define LOG_CRITICAL(logger, ...) logger->critical(__VA_ARGS__)

} // namespace Soverx

#endif // SOVERX_LOGGER_H

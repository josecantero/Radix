#ifndef RADIX_RATE_LIMITER_H
#define RADIX_RATE_LIMITER_H

#include <deque>
#include <mutex>
#include <cstdint>

namespace Radix {

/**
 * @brief Rate limiter using sliding window algorithm
 * 
 * Tracks request timestamps and allows requests only if under the limit
 * within a 60-second window. Thread-safe.
 */
class RateLimiter {
public:
    /**
     * @brief Construct a new Rate Limiter
     * @param requestsPerMinute Maximum requests allowed per 60 seconds
     */
    explicit RateLimiter(int requestsPerMinute = 100);
    
    /**
     * @brief Check if a request is allowed and record it if so
     * @return true if request is allowed, false if rate limit exceeded
     */
    bool allowRequest();
    
    /**
     * @brief Set the rate limit
     * @param requestsPerMinute New limit
     */
    void setLimit(int requestsPerMinute);
    
    /**
     * @brief Get remaining requests in current window
     * @return Number of requests still allowed
     */
    int getRemainingRequests();
    
    /**
     * @brief Get current request count in window
     * @return Number of requests in the last 60 seconds
     */
    int getCurrentRequestCount();

private:
    std::deque<uint64_t> requestTimestamps; // timestamps in milliseconds
    int limit;
    mutable std::mutex mutex;
    
    /**
     * @brief Remove timestamps older than 60 seconds
     */
    void cleanup();
    
    /**
     * @brief Get current time in milliseconds
     * @return Current timestamp
     */
    static uint64_t getCurrentTimeMs();
};

} // namespace Radix

#endif // RADIX_RATE_LIMITER_H

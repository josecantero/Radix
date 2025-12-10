#include "RateLimiter.h"
#include <chrono>
#include <algorithm>

namespace Radix {

RateLimiter::RateLimiter(int requestsPerMinute) : limit(requestsPerMinute) {}

bool RateLimiter::allowRequest() {
    std::lock_guard<std::mutex> lock(mutex);
    
    cleanup();
    
    // Check if we're under the limit
    if (static_cast<int>(requestTimestamps.size()) >= limit) {
        return false;
    }
    
    // Record this request
    requestTimestamps.push_back(getCurrentTimeMs());
    return true;
}

void RateLimiter::setLimit(int requestsPerMinute) {
    std::lock_guard<std::mutex> lock(mutex);
    limit = requestsPerMinute;
}

int RateLimiter::getRemainingRequests() {
    std::lock_guard<std::mutex> lock(mutex);
    cleanup();
    int remaining = limit - static_cast<int>(requestTimestamps.size());
    return remaining > 0 ? remaining : 0;
}

int RateLimiter::getCurrentRequestCount() {
    std::lock_guard<std::mutex> lock(mutex);
    cleanup();
    return static_cast<int>(requestTimestamps.size());
}

void RateLimiter::cleanup() {
    uint64_t now = getCurrentTimeMs();
    uint64_t windowStart = now - 60000; // 60 seconds in milliseconds
    
    // Remove all timestamps older than 60 seconds
    while (!requestTimestamps.empty() && requestTimestamps.front() < windowStart) {
        requestTimestamps.pop_front();
    }
}

uint64_t RateLimiter::getCurrentTimeMs() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

} // namespace Radix

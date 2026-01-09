cmake_minimum_required(VERSION 3.10)

# Test executable
add_executable(soverx_tests
    test_main.cpp
    test_crypto.cpp
    test_transaction.cpp
    test_block.cpp
    test_blockchain.cpp
    test_ratelimiter.cpp
    ../src/api/RateLimiter.cpp
)

# Link against soverx_core library and gtest
target_link_libraries(soverx_tests
    soverx_core
    GTest::gtest_main
    GTest::gmock
)

# Include directories
target_include_directories(soverx_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${RANDOMX_INCLUDE_DIR}
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(soverx_tests)

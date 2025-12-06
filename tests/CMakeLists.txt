cmake_minimum_required(VERSION 3.10)

# Test executable
add_executable(radix_tests
    test_main.cpp
    test_crypto.cpp
    test_transaction.cpp
    test_block.cpp
    test_blockchain.cpp
)

# Link against radix_core library and gtest
target_link_libraries(radix_tests
    radix_core
    GTest::gtest_main
    GTest::gmock
)

# Include directories
target_include_directories(radix_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${RANDOMX_INCLUDE_DIR}
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(radix_tests)

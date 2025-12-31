#!/bin/bash

# Script to migrate remaining cout/cerr to Logger in Node.cpp
# This is a helper script to speed up the migration

cd "$(dirname "$0")/.."

FILE="src/networking/Node.cpp"

# Backup original
cp "$FILE" "${FILE}.backup"

# Replace std::cout with LOG_INFO for general messages
sed -i 's/std::cout << "\([^"]*\)" << std::endl;/LOG_INFO(Logger::network(), "\1");/g' "$FILE"

# Replace std::cerr with LOG_ERROR for errors  
sed -i 's/std::cerr << "\([^"]*\)" << std::endl;/LOG_ERROR(Logger::network(), "\1");/g' "$FILE"

# Handle complex patterns with variables - these need manual review
echo "Remaining complex patterns to migrate manually:"
grep "std::cout\|std::cerr" "$FILE" | head -20

echo "Migration script completed. Review changes and test build."

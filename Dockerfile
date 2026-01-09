# Multi-stage Dockerfile for Radix Blockchain
# Stage 1: Builder - Install dependencies and compile
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Build and install RandomX
WORKDIR /tmp/randomx
RUN git clone https://github.com/tevador/RandomX.git . && \
    mkdir build && cd build && \
    cmake -DARCH=native .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Copy source code
WORKDIR /soverx
COPY . .

# Build Radix
RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Stage 2: Runtime - Minimal image with only the binary
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy RandomX library from builder
COPY --from=builder /usr/local/lib/librandomx.* /usr/local/lib/
RUN ldconfig

# Copy compiled binary
COPY --from=builder /soverx/build/soverx_node /usr/local/bin/soverx_node

# Create data directory
RUN mkdir -p /soverx/data
WORKDIR /soverx

# Expose P2P and RPC ports
EXPOSE 8080 8090

# Default command: start server with RPC enabled
CMD ["soverx_node", "--server", "--rpc"]

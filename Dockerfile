FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# -----------------------------
# System dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    ca-certificates \
    libssl-dev \
    openssl \
    python3 \
    perl \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Build & install liboqs
# -----------------------------
WORKDIR /opt

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git

WORKDIR /opt/liboqs

RUN mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOPENSSL_ROOT_DIR=/usr \
          -DOPENSSL_INCLUDE_DIR=/usr/include \
          .. && \
    make -j$(nproc) && \
    make install

# -----------------------------
# Build Kyber service
# -----------------------------
WORKDIR /app

# Download header-only HTTP library
RUN wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

# Copy application files
COPY main.cpp .
COPY CMakeLists.txt .

# IMPORTANT: Explicitly point CMake to liboqs config
RUN cmake -DOQS_DIR=/usr/local/lib/cmake/liboqs . && make

# Render expects a listening port
EXPOSE 8080

# Start service
CMD ["./kyber_service"]

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Build and install liboqs
# -----------------------------
WORKDIR /opt

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git

WORKDIR /opt/liboqs
RUN mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && \
    make install

# -----------------------------
# Build Kyber service
# -----------------------------
WORKDIR /app

# Download cpp-httplib (header-only)
RUN wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

# Copy app source
COPY main.cpp .
COPY CMakeLists.txt .

# Configure and build app
RUN cmake -DCMAKE_PREFIX_PATH=/usr/local . && make

# Render expects the app to listen on a port
EXPOSE 8080

# Start service
CMD ["./kyber_service"]

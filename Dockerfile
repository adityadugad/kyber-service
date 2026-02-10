FROM ubuntu:22.04

# Install build dependencies
RUN apt update && apt install -y \
    cmake \
    git \
    gcc \
    g++ \
    libssl-dev \
    wget

# -------------------------------
# Build and install liboqs
# -------------------------------
RUN git clone https://github.com/open-quantum-safe/liboqs.git
WORKDIR /liboqs
RUN mkdir build && cd build && \
    cmake -DOQS_BUILD_SHARED_LIBS=ON .. && \
    make && make install

# -------------------------------
# Build Kyber service
# -------------------------------
WORKDIR /app

# Download cpp-httplib header (header-only)
RUN wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

# Copy source files
COPY main.cpp .
COPY CMakeLists.txt .

# Build service
RUN cmake . && make

# Expose service port
EXPOSE 8080

# Start Kyber service
CMD ["./kyber_service"]

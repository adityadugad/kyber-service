FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# -------------------------------------------------
# System dependencies (Render-safe)
# -------------------------------------------------
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

# -------------------------------------------------
# Build & install liboqs (Kyber / ML-KEM ONLY)
# -------------------------------------------------
WORKDIR /opt

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git

WORKDIR /opt/liboqs

RUN mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOPENSSL_ROOT_DIR=/usr \
          -DOPENSSL_INCLUDE_DIR=/usr/include \
          -DOQS_ENABLE_SIG=OFF \
          -DOQS_ENABLE_KEM=ON \
          -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
          -DOQS_ENABLE_KEM_FRODOKEM=OFF \
          -DOQS_ENABLE_KEM_BIKE=OFF \
          -DOQS_ENABLE_KEM_NTRU=OFF \
          -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
          -DOQS_ENABLE_KEM_HQC=OFF \
          -DOQS_ENABLE_TESTING=OFF \
          -DOQS_BUILD_ONLY_LIB=ON \
          .. && \
    make -j$(nproc) && \
    make install

# -------------------------------------------------
# Build your Kyber service
# -------------------------------------------------
WORKDIR /app

# Header-only HTTP library
RUN wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

COPY main.cpp .
COPY CMakeLists.txt .

# 🔑 Correct CMake invocation for Render
RUN cmake -DCMAKE_PREFIX_PATH=/usr/local . && make

# Render requirement
EXPOSE 8080

CMD ["./kyber_service"]

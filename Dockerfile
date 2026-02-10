FROM ubuntu:22.04

RUN apt update && apt install -y \
    cmake \
    git \
    gcc \
    g++ \
    libssl-dev

# Install liboqs
RUN git clone https://github.com/open-quantum-safe/liboqs.git
WORKDIR /liboqs
RUN mkdir build && cd build && \
    cmake -DOQS_BUILD_SHARED_LIBS=ON .. && \
    make && make install

# Header-only HTTP library
WORKDIR /app
RUN git clone https://github.com/yhirose/cpp-httplib.git
COPY main.cpp .
COPY CMakeLists.txt .

RUN cmake . && make

EXPOSE 8080
CMD ["./kyber_service"]

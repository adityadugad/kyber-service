cmake_minimum_required(VERSION 3.10)
project(kyber_service LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find liboqs
find_package(OQS REQUIRED)

# Build executable
add_executable(kyber_service main.cpp)

# For httplib.h
target_include_directories(kyber_service
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link liboqs (modern CMake target)
target_link_libraries(kyber_service
    PRIVATE OQS::oqs
)

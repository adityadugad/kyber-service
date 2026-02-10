cmake_minimum_required(VERSION 3.10)
project(kyber_service)

# Find liboqs
find_package(OQS REQUIRED)

# Build executable
add_executable(kyber_service main.cpp)

# Allow compiler to find httplib.h in current directory
target_include_directories(kyber_service
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against liboqs
target_link_libraries(kyber_service oqs)

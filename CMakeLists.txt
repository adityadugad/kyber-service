cmake_minimum_required(VERSION 3.10)
project(kyber_service LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Correct package name
find_package(liboqs CONFIG REQUIRED)

add_executable(kyber_service main.cpp)

target_include_directories(kyber_service
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

# ✅ CORRECT TARGET NAME (THIS IS THE KEY)
target_link_libraries(kyber_service
    PRIVATE OQS::oqs
)

cmake_minimum_required(VERSION 3.10)
project(kyber_service LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ✅ CORRECT package name
find_package(liboqs CONFIG REQUIRED)

add_executable(kyber_service main.cpp)

target_include_directories(kyber_service
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

# ✅ CORRECT target name
target_link_libraries(kyber_service
    PRIVATE liboqs::oqs
)

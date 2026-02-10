cmake_minimum_required(VERSION 3.10)
project(kyber_service)

find_package(OQS REQUIRED)

add_executable(kyber_service main.cpp)
target_link_libraries(kyber_service oqs)

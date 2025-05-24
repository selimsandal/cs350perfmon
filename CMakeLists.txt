cmake_minimum_required(VERSION 3.31)
project(cs350perfmon)

set(CMAKE_CXX_STANDARD 26)

add_executable(cs350perfmon main.cpp)

find_package(Threads REQUIRED)
target_link_libraries(cs350perfmon ${CMAKE_THREAD_LIBS_INIT})
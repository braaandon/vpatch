cmake_minimum_required(VERSION 3.29)
project(patcher)

add_subdirectory(ext/minhook)

set(CMAKE_CXX_STANDARD 20)

add_library(patcher SHARED src/library.cpp)
target_link_libraries(patcher PRIVATE minhook)
target_include_directories(patcher PRIVATE ext ext/minhook/include)

cmake_minimum_required(VERSION 3.9)
project(xdk_extractor)

set(CMAKE_CXX_STANDARD 17)

add_executable(xdk_extractor main.cpp coff.cpp coff.h)
cmake_minimum_required(VERSION 3.10)
project(xdk-extractor)

set(CMAKE_CXX_STANDARD 17)

add_executable(xdk-extractor main.cpp coff.cpp coff.h)
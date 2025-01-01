cmake_minimum_required(VERSION 3.29)
project(ReadDex)

set(CMAKE_CXX_STANDARD 20)

add_executable(ReadDex main.cpp
        DexFile.h
        DexFile.cpp
        Leb128.h
)

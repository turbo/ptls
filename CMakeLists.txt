cmake_minimum_required(VERSION 3.17)
project(ptls C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(client
        client.c
        mincrypt.c
        nutls.c
        nutls.h
        server.c)

add_executable(server
        server.c
        mincrypt.c
        nutls.c
        nutls.h)
cmake_minimum_required(VERSION 2.8)

project(wpa_decode)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -lpcap -lcrypto")

add_executable(wpa_decode main.c fastpbkdf2.c)

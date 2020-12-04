cmake_minimum_required(VERSION 3.13...3.16)

project(atx-dis)

add_executable(atx-dis atx-dis.c atx-dis.h linq-dis.h)

install(TARGETS atx-dis RUNTIME DESTINATION bin)
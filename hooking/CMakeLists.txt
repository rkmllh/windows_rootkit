cmake_minimum_required(VERSION 3.24)

project(rootkit)

add_library(
	rootkit SHARED
    	src/dllmain.c
    	src/framework.h
    	src/pch.c
    	src/pch.h
)

target_include_directories(
	rootkit PUBLIC
    	${CMAKE_CURRENT_SOURCE_DIR}/..
)

cmake_minimum_required(VERSION 3.10)

project(dll_injector C)

set(SOURCES
	src/injector.c
	src/injector.h
	src/macro.h
	src/main.c
	src/process.c
	src/process.h
)

add_executable(dll_injector ${SOURCES})

project(init)

add_library(
	init SHARED
    	src/dllmain.cpp
    	src/framework.h
    	src/pch.cpp
    	src/pch.h
)

target_include_directories(
	init PUBLIC
    	${CMAKE_CURRENT_SOURCE_DIR}/..
)

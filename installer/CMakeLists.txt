project(installer)

add_executable(
	installer
    src/main.c
	src/resource.h
)

target_include_directories(
	installer PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/..
)

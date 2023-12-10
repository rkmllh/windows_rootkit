#pragma once
#include <windows.h>

typedef int pid_t;

/*
* @param [path_dll] path to malicious dll
* @param [pid] pid of target process
* @param [b_wait] waiting for end of thread
*/

int injector(
	char* path_dll,
	pid_t pid,
	BOOL b_wait
);

#pragma once
#include "macro.h"

/*
* @param [proc_name] name of target process
*/

pid_t get_pid_by_name(
	const char* proc_name
);

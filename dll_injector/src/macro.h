#pragma once
#include <string.h>
#include <stdio.h>

typedef int pid_t;

#define handle_error(what)		\
	do{fprintf(stderr, "handle_error in %s <%d>\n", what, GetLastError()); exit(1);} while(0);

#define memzero(base,size)      \
	memset(base, 0, size)

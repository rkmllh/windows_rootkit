#include <stdio.h>
#include "injector.h"
#include "process.h"

//Print and die
void usage(char* process);

int main(
	int argc,
	char** argv
)
{
	BOOL bit = 0;

	if (argc != 4 && argc != 3)
		usage(argv[0]);

	if (argc == 4)
	{
		switch (argv[3][0])
		{
		case 'W':
		case 'w':
			bit = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	injector(argv[1], get_pid_by_name(argv[2]), bit);

	exit(0);
}

void usage(char* process)
{
	fprintf(stderr, 
					"usage <%s> <dll path> <process name> <optional parameter>\n"
					"\n\t--w Waiting for end of injected thread\n",
			process);
	exit(1);
}

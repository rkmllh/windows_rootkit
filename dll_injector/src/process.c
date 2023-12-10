#include <windows.h>
#include <TlHelp32.h>
#include "process.h"

pid_t get_pid_by_name(
	const char* proc_name
)
{
	pid_t pid = 0;
	HANDLE h_snapshot = NULL;
	PROCESSENTRY32 process_entry_32;
	BOOL b_found = 0;

	memzero(&process_entry_32, sizeof(PROCESSENTRY32));
	process_entry_32.dwSize = sizeof(PROCESSENTRY32);

	h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h_snapshot == INVALID_HANDLE_VALUE)
		handle_error("CreateToolhelp32Snapshot");

	if (Process32First(h_snapshot, &process_entry_32) == 0)
		handle_error("Process32First");

	//Find your processes
	do
	{
		if (strcmp(process_entry_32.szExeFile, proc_name) == 0)
		{
			pid = process_entry_32.th32ProcessID;
			b_found = 1;
		}

	} while (Process32Next(h_snapshot, &process_entry_32) != 0 && b_found == 0);

	CloseHandle(h_snapshot);

	return pid;
}

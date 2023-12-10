#define _CRT_SECURE_NO_WARNINGS
#include "injector.h"
#include "process.h"
#include "macro.h"

int injector(
	char* path_dll,
	pid_t pid,
	BOOL b_wait
)
{
	HANDLE h_process = NULL;
	LPVOID p_path_dll = NULL;
	HANDLE h_thread = NULL;
	HMODULE h_kernel_library = NULL;
	FARPROC h_procedure = NULL;

	BOOL bit = 0;
	SIZE_T written_bytes = 0;
	
	h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (h_process == NULL)
		handle_error("OpenProcess");

	p_path_dll = VirtualAllocEx(h_process,
		NULL,
		(strlen(path_dll) * sizeof(char)) + sizeof(char),
		MEM_COMMIT,
		PAGE_READWRITE		//Read and write into new page
	);

	if (p_path_dll == NULL)
		handle_error("VirtualAllocEx");

	bit = WriteProcessMemory(
		h_process,
		p_path_dll,
		(LPVOID)path_dll,
		strlen(path_dll) * sizeof(char) + sizeof(char),
		&written_bytes
	);

	if (written_bytes != strlen(path_dll) * sizeof(char) + sizeof(char)
		|| bit == 0)
		handle_error("WriteProcessMemory");

	h_kernel_library = GetModuleHandleA("kernel32.dll");

	if (h_kernel_library == NULL)
		handle_error("GetModuleHandleA");

	h_procedure = GetProcAddress(h_kernel_library, "LoadLibraryA");
	
	if(h_procedure == NULL)
		handle_error("LoadLibraryA");
	
	h_thread = CreateRemoteThread(
		h_process,
		NULL,		//Default sa
		0,			//Default stack size
		(LPTHREAD_START_ROUTINE)h_procedure,
		p_path_dll,
		0,
		NULL
	);

	if (h_thread == NULL)
		handle_error("CreateRemoteThread");

	if (b_wait != 0)
		WaitForSingleObject(h_thread, INFINITE);

	bit = VirtualFreeEx(
		h_process,
		p_path_dll,
		0,
		MEM_RELEASE
	);

	if (bit == 0)
		handle_error("VirtualFreeEx");

	CloseHandle(h_process);
	CloseHandle(h_thread);
	CloseHandle(h_kernel_library);

	return NO_ERROR;
}

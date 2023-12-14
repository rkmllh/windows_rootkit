// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "pch.h"
#include <time.h>
#include <stdio.h>

#define INLINE      inline
#define STATIC      static
#define SIZEOF(el)  sizeof(el)
#define READONLY    const
#define PROCEDURE   void

#define OFFSET_YEAR(year)										\
	year += 0x0000076c

#define MEMCOPY(src, dest, size)								\
	memcpy(src,dest,size)

#define NTSIGNATURE(base)										\
	((LPVOID)((BYTE*)base + ((IMAGE_DOS_HEADER*)base)->e_lfanew))

#define IMAGEFILEHEADEROFFSET(base)								\
	(LPVOID)(((BYTE*)NTSIGNATURE(base)) + SIZEOF(DWORD))

#define IMAGEOPTIONALHEADEROFFSET(base)							\
	(LPVOID)((BYTE*)IMAGEFILEHEADEROFFSET(base) + SIZEOF(IMAGE_FILE_HEADER))

#define IMAGESECTIONHEADEROFFSET(base)							\
	(LPVOID)((BYTE*)IMAGEOPTIONALHEADEROFFSET(base) + SIZEOF(IMAGE_OPTIONAL_HEADER))

/*
*   IMAGE_IMPORT_DESCRIPTOR is Import Directory Table
*   for import sections, here it starts import informations.
*	It resolves references imported by DLL's.
*/
typedef IMAGE_IMPORT_DESCRIPTOR     IMPORT_DIRECTORY_TABLE;

PROCEDURE write_import_address_table(READONLY LPVOID base, READONLY IMAGE_OPTIONAL_HEADER* image_optional_header);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		MessageBoxA(0, "Injected", "Injected", 0);
		VOID* base = GetModuleHandle(NULL);
		IMAGE_OPTIONAL_HEADER* ioh = (IMAGE_OPTIONAL_HEADER*)IMAGEOPTIONALHEADEROFFSET(base);
		write_import_address_table(base, ioh);
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		break;
    }
    return TRUE;
}

FARPROC hooked(HMODULE dll, LPCSTR x)
{
	// Manage cases
	if (strcmp(x, "DeleteFile"))
	{

	}
	return GetProcAddress(dll, x);
}

PROCEDURE write_import_address_table(READONLY LPVOID base, READONLY IMAGE_OPTIONAL_HEADER* image_optional_header)
{
	DWORD oldProtect = 0;
	time_t import_time = 0;
	struct tm* tm_import_time = NULL;

	IMAGE_DATA_DIRECTORY* image_data_directory = (IMAGE_DATA_DIRECTORY*)image_optional_header->DataDirectory;
	IMPORT_DIRECTORY_TABLE* import_directory_table = (IMPORT_DIRECTORY_TABLE*)((BYTE*)base + image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	IMAGE_THUNK_DATA* original_first_thunk_data = NULL;
	IMAGE_THUNK_DATA* first_thunk_data = NULL;

	IMAGE_IMPORT_BY_NAME* procedure = NULL;

	READONLY CHAR* proc_name = NULL;
	READONLY BYTE* dll_name = NULL;

	ULONGLONG proc_address = 0;

	/*
	*   Now import_directory_table points to array of import directory entries.
	*   Each directory entries describes a DLL.
	*/

	/*Check number of directories*/
	if (IMAGE_DIRECTORY_ENTRY_IMPORT < image_optional_header->NumberOfRvaAndSizes)
	{
		if (image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress &&
			image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			while (import_directory_table->OriginalFirstThunk)
			{
				dll_name = (BYTE*)base + import_directory_table->Name;
				original_first_thunk_data = (IMAGE_THUNK_DATA*)((DWORD_PTR)base + import_directory_table->OriginalFirstThunk);
				first_thunk_data = (IMAGE_THUNK_DATA*)((DWORD_PTR)base + import_directory_table->FirstThunk);

				while (!(original_first_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					&& original_first_thunk_data->u1.AddressOfData)
				{
					procedure = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)base + original_first_thunk_data->u1.AddressOfData);

					proc_name = procedure->Name;
					proc_address = first_thunk_data->u1.Function;

					if (strcmp(proc_name, "GetProcAddress") == 0)
					{
#ifndef _WIN64
						VirtualProtect((LPVOID) & (first_thunk_data->u1.Function), sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect);
						first_thunk_data->u1.Function = (DWORD)hooked;
						VirtualProtect((LPVOID) & (first_thunk_data->u1.Function), sizeof(DWORD), oldProtect, &oldProtect);
#else
						VirtualProtect((LPVOID) & (first_thunk_data->u1.Function), sizeof(unsigned long long), PAGE_EXECUTE_READWRITE, &oldProtect);
						first_thunk_data->u1.Function = (unsigned long long)hooked;
						VirtualProtect((LPVOID) & (first_thunk_data->u1.Function), sizeof(unsigned long long), oldProtect, &oldProtect);
#endif // !_WIN64
					}

					original_first_thunk_data++;
					first_thunk_data++;
				}

				++import_directory_table;
			}
		}
	}

	return;
}

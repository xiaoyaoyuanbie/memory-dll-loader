#include <stdio.h>
#include <Windows.h>

typedef LPVOID(WINAPI* VirtualAllocType)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI* MapViewOfFileType)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);

VirtualAllocType pVirtualAlloc = NULL;
MapViewOfFileType pMapViewOfFile = NULL;

void InitializeDynamicFunctions()
{
	HMODULE hKernel32 = LoadLibraryA("Kernel32.dll");
	if (hKernel32 == NULL)
	{
		printf("Failed to load Kernel32.dll\n");
		return;
	}

	pVirtualAlloc = (VirtualAllocType)GetProcAddress(hKernel32, "VirtualAlloc");
	if (pVirtualAlloc == NULL)
	{
		printf("Failed to get VirtualAlloc address\n");
		return;
	}

	pMapViewOfFile = (MapViewOfFileType)GetProcAddress(hKernel32, "MapViewOfFile");
	if (pMapViewOfFile == NULL)
	{
		printf("Failed to get MapViewOfFile address\n");
		return;
	}
}

PIMAGE_NT_HEADERS getnthead(char* file)
{
	PIMAGE_DOS_HEADER Pdos = (PIMAGE_DOS_HEADER)file;
	PIMAGE_NT_HEADERS Pnt = (PIMAGE_NT_HEADERS)((DWORD)Pdos + Pdos->e_lfanew);
	return Pnt;
}

HANDLE OpenPeByFileName(const char* filename)
{
	HANDLE hfile, hmapfile, lpmapaddress = NULL;
	hfile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open file: %s\n", filename);
		return NULL;
	}

	DWORD filesize = GetFileSize(hfile, NULL);
	hmapfile = CreateFileMappingA(hfile, NULL, PAGE_READONLY, 0, filesize, NULL);
	if (hmapfile == NULL)
	{
		printf("Failed to create file mapping\n");
		CloseHandle(hfile);
		return NULL;
	}

	lpmapaddress = pMapViewOfFile(hmapfile, FILE_MAP_READ, 0, 0, filesize);
	CloseHandle(hfile);
	if (lpmapaddress != NULL)
	{
		return lpmapaddress;
	}
	return NULL;
}

bool importtable(char* chbaseaddress)
{
	PIMAGE_NT_HEADERS Pnt = getnthead(chbaseaddress);
	if (Pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
	{
		return TRUE;
	}

	PIMAGE_IMPORT_DESCRIPTOR pimporttable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)chbaseaddress + Pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	char* lpdllname = NULL;
	HMODULE hdll;
	PIMAGE_THUNK_DATA lpimportnamearray = NULL;
	PIMAGE_THUNK_DATA lpimportfuncaddrarray = NULL;
	PIMAGE_IMPORT_BY_NAME lpimportbyname = NULL;
	FARPROC lpfuncaddress = NULL;
	DWORD i;

	while (pimporttable->OriginalFirstThunk != 0)
	{
		lpdllname = (char*)((DWORD)chbaseaddress + pimporttable->Name);
		hdll = GetModuleHandleA(lpdllname);
		if (hdll == NULL)
		{
			hdll = LoadLibraryA(lpdllname);
			if (hdll == NULL)
			{
				printf("Failed to load DLL: %s\n", lpdllname);
				pimporttable++;
				continue;
			}
		}

		i = 0;
		lpimportnamearray = (PIMAGE_THUNK_DATA)((DWORD)chbaseaddress + pimporttable->OriginalFirstThunk);
		lpimportfuncaddrarray = (PIMAGE_THUNK_DATA)((DWORD)chbaseaddress + pimporttable->FirstThunk);

		while (lpimportnamearray[i].u1.AddressOfData != 0)
		{
			if (0x80000000 & lpimportnamearray[i].u1.AddressOfData)
			{
				lpfuncaddress = GetProcAddress(hdll, (LPCSTR)(lpimportnamearray[i].u1.Ordinal & 0x0000ffff));
			}
			else
			{
				lpimportbyname = (PIMAGE_IMPORT_BY_NAME)((DWORD)chbaseaddress + lpimportnamearray[i].u1.AddressOfData);
				lpfuncaddress = GetProcAddress(hdll, lpimportbyname->Name);
			}

			lpimportfuncaddrarray[i].u1.Function = (DWORD)lpfuncaddress;
			i++;
		}
		pimporttable++;
	}
	return TRUE;
}

bool CallDllMain(char* chBaseAddress, DWORD reason)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);

	typedef BOOL (WINAPI* DllMainPtr)(HINSTANCE, DWORD, LPVOID);
	DllMainPtr pDllMain = (DllMainPtr)(chBaseAddress + pNt->OptionalHeader.AddressOfEntryPoint);

	if (pDllMain == NULL)
		return FALSE;

	return pDllMain((HINSTANCE)chBaseAddress, reason, NULL);
}

DWORD GetOriginalImageBase(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	return pNt->OptionalHeader.ImageBase;
}

bool reloctiontable(char* chbaseaddress, DWORD dwOriginalImageBase)
{
	PIMAGE_NT_HEADERS pnt = getnthead(chbaseaddress);
	DWORD relocDirAddr = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (relocDirAddr == 0)
	{
		printf("[*] No relocation directory found\n");
		return TRUE;
	}

	// 计算实际加载地址与首选基址的差值
	DWORD dwDelta = (DWORD)chbaseaddress - dwOriginalImageBase;
	if (dwDelta == 0)
	{
		printf("[*] Loaded at preferred base address, no relocation needed\n");
		return TRUE;
	}

	printf("[*] Delta: 0x%X (Original: 0x%X, Current: 0x%X)\n", dwDelta, dwOriginalImageBase, (DWORD)chbaseaddress);

	PIMAGE_BASE_RELOCATION ploc = (PIMAGE_BASE_RELOCATION)(chbaseaddress + relocDirAddr);
	int relocCount = 0;

	while (ploc->VirtualAddress != 0 && ploc->SizeOfBlock != 0)
	{
		WORD* plocdata = (WORD*)((PBYTE)ploc + sizeof(IMAGE_BASE_RELOCATION));
		int numofreloc = (ploc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < numofreloc; i++)
		{
			// IMAGE_REL_BASED_HIGHLOW = 3 (0x3000)
			if ((plocdata[i] & 0x0000f000) == 0x00003000)
			{
				DWORD* paddress = (DWORD*)((PBYTE)chbaseaddress + ploc->VirtualAddress + (plocdata[i] & 0xfff));
				*paddress = *paddress + dwDelta;
				relocCount++;
			}
		}
		ploc = (PIMAGE_BASE_RELOCATION)((PBYTE)ploc + ploc->SizeOfBlock);
	}

	printf("[*] Applied %d relocations\n", relocCount);
	return TRUE;
}

PCHAR filetoimage(char* file)
{
	PIMAGE_NT_HEADERS Pnt = getnthead(file);
	DWORD sizeofimage = Pnt->OptionalHeader.SizeOfImage;
	PCHAR pimagebuffer = (PCHAR)pVirtualAlloc(NULL, sizeofimage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pimagebuffer == NULL)
	{
		printf("Failed to allocate memory\n");
		return NULL;
	}

	memset(pimagebuffer, 0, sizeofimage);
	memcpy(pimagebuffer, file, Pnt->OptionalHeader.SizeOfHeaders);

	ULONG numberofsections = Pnt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER psection = IMAGE_FIRST_SECTION(Pnt);

	for (ULONG i = 0; i < numberofsections; i++)
	{
		memcpy(pimagebuffer + psection->VirtualAddress, file + psection->PointerToRawData, psection->SizeOfRawData);
		psection++;
	}

	return pimagebuffer;
}

FARPROC GetExportFunction(char* chBaseAddress, const char* functionName)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);

	DWORD exportDirAddr = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirAddr == 0)
	{
		printf("No export table found\n");
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(chBaseAddress + exportDirAddr);

	if (pExportDir->NumberOfFunctions == 0)
		return NULL;

	DWORD* pAddressOfFunctions = (DWORD*)(chBaseAddress + pExportDir->AddressOfFunctions);
	DWORD* pAddressOfNames = (DWORD*)(chBaseAddress + pExportDir->AddressOfNames);
	WORD* pAddressOfNameOrdinals = (WORD*)(chBaseAddress + pExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
	{
		char* name = (char*)(chBaseAddress + pAddressOfNames[i]);

		if (strcmp(name, functionName) == 0)
		{
			WORD ordinal = pAddressOfNameOrdinals[i];
			DWORD funcOffset = pAddressOfFunctions[ordinal];
			return (FARPROC)(chBaseAddress + funcOffset);
		}
	}

	printf("Function '%s' not found in export table\n", functionName);
	return NULL;
}

FARPROC GetExportFunctionByOrdinal(char* chBaseAddress, WORD ordinal)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);

	DWORD exportDirAddr = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirAddr == 0)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(chBaseAddress + exportDirAddr);

	DWORD* pAddressOfFunctions = (DWORD*)(chBaseAddress + pExportDir->AddressOfFunctions);

	DWORD index = ordinal - pExportDir->Base;
	if (index >= pExportDir->NumberOfFunctions)
		return NULL;

	return (FARPROC)(chBaseAddress + pAddressOfFunctions[index]);
}

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		printf("Usage: %s <dll_path> <function_name>\n", argv[0]);
		printf("Example: %s C:\\test.dll Add\n", argv[0]);
		return 1;
	}

	const char* dllPath = argv[1];
	const char* functionName = argv[2];

	InitializeDynamicFunctions();

	printf("[*] Loading DLL: %s\n", dllPath);
	HANDLE lpmapaddress = OpenPeByFileName(dllPath);
	if (lpmapaddress == NULL)
	{
		printf("[-] Failed to open PE file\n");
		return 1;
	}

	printf("[*] Converting file to image...\n");
	PCHAR image = filetoimage((char*)lpmapaddress);
	if (image == NULL)
	{
		printf("[-] Failed to create image in memory\n");
		return 1;
	}

	// 在修改之前保存原始 ImageBase
	printf("[*] Saving original ImageBase: 0x%X\n", GetOriginalImageBase((char*)lpmapaddress));
	DWORD dwOriginalImageBase = GetOriginalImageBase((char*)lpmapaddress);

	printf("[*] Processing relocations...\n");
	reloctiontable(image, dwOriginalImageBase);

	printf("[*] Processing imports...\n");
	importtable(image);

	printf("[*] Calling DllMain (DLL_PROCESS_ATTACH)...\n");
	if (!CallDllMain(image, DLL_PROCESS_ATTACH))
	{
		printf("[-] DllMain returned FALSE\n");
	}

	printf("[*] Getting export function: %s\n", functionName);
	typedef int (*TestFuncType)(int, int);
	TestFuncType pFunc = (TestFuncType)GetExportFunction(image, functionName);

	if (pFunc != NULL)
	{
		printf("[+] Function found at address: 0x%p\n", pFunc);
		printf("[*] Calling function...\n");
		int result = pFunc(10, 20);
		printf("[+] Function returned: %d\n", result);
	}
	else
	{
		printf("[-] Function not found\n");
	}

	printf("[*] Calling DllMain (DLL_PROCESS_DETACH)...\n");
	CallDllMain(image, DLL_PROCESS_DETACH);

	printf("[*] Done. Press any key to exit...\n");
	getchar();

	return 0;
}

// dllmain.cpp : DLL Entry Point
#include "pch.h"

#include <Windows.h>
#include <stdio.h>

// Export function - Integer addition
extern "C" __declspec(dllexport) int Add(int a, int b)
{
	printf("    [DLL] Add(%d, %d) called\n", a, b);
	return a + b;
}

// Export function - Integer subtraction
extern "C" __declspec(dllexport) int Sub(int a, int b)
{
	printf("    [DLL] Sub(%d, %d) called\n", a, b);
	return a - b;
}

// Export function - Integer multiplication
extern "C" __declspec(dllexport) int Mul(int a, int b)
{
	printf("    [DLL] Mul(%d, %d) called\n", a, b);
	return a * b;
}

// Export function - Show message
extern "C" __declspec(dllexport) void ShowMessage(const char* msg)
{
	printf("    [DLL] ShowMessage: %s\n", msg);
}

// Export function - Get value
extern "C" __declspec(dllexport) int GetValue()
{
	printf("    [DLL] GetValue() called\n");
	return 42;
}

// Export function - Exported by ordinal
extern "C" __declspec(dllexport) int OrdinalFunc()
{
	printf("    [DLL] OrdinalFunc() called (exported by ordinal)\n");
	return 999;
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		printf("    [DLL] DLL_PROCESS_ATTACH - DLL loaded!\n");
		printf("    [DLL] Module handle: 0x%p\n", hModule);
		break;
	case DLL_THREAD_ATTACH:
		printf("    [DLL] DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		printf("    [DLL] DLL_THREAD_DETACH\n");
		break;
	case DLL_PROCESS_DETACH:
		printf("    [DLL] DLL_PROCESS_DETACH - DLL unloading!\n");
		break;
	}
	return TRUE;
}

// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#include <Windows.h>
#include <stdio.h>

// 导出函数 - 整数加法
extern "C" __declspec(dllexport) int Add(int a, int b)
{
	printf("    [DLL] Add(%d, %d) called\n", a, b);
	return a + b;
}

// 导出函数 - 整数减法
extern "C" __declspec(dllexport) int Sub(int a, int b)
{
	printf("    [DLL] Sub(%d, %d) called\n", a, b);
	return a - b;
}

// 导出函数 - 整数乘法
extern "C" __declspec(dllexport) int Mul(int a, int b)
{
	printf("    [DLL] Mul(%d, %d) called\n", a, b);
	return a * b;
}

// 导出函数 - 显示消息
extern "C" __declspec(dllexport) void ShowMessage(const char* msg)
{
	printf("    [DLL] ShowMessage: %s\n", msg);
}

// 导出函数 - 获取值
extern "C" __declspec(dllexport) int GetValue()
{
	printf("    [DLL] GetValue() called\n");
	return 42;
}

// 导出函数 - 通过序号导出
extern "C" __declspec(dllexport) int OrdinalFunc()
{
	printf("    [DLL] OrdinalFunc() called (exported by ordinal)\n");
	return 999;
}

// DLL 入口点
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


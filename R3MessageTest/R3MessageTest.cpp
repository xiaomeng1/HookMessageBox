// R3MessageTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
//764EEA5F    空闲 7650221F   =  1 37C0

TCHAR arry[] = L"111222";

int main()
{
    DWORD dwHookAddress = (DWORD)GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
    DWORD value = *(PULONG)dwHookAddress;

    MessageBox(NULL, L"22", arry, NULL);
}


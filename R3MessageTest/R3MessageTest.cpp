// R3MessageTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

int main()
{
    DWORD dwHookAddress = (DWORD)GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
    DWORD value = *(PULONG)dwHookAddress;
    __asm
    {
        int 3;
    }
    MessageBox(NULL, NULL, NULL, NULL);
}


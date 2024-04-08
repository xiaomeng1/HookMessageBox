// one.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include "malloc.h"
#include <windows.h>
#include <winioctl.h>

#define PATCH_LENGTH 5
DWORD dwHookAddress = 0;
DWORD dwRetAddress = 0;
TCHAR szNewText[] = L"InlineHook";

#define IN_BUFFER_MAXLENGTH  0x10   // 输入缓存最大长度
#define OUT_BUFFER_MAXLENGTH 0x10   // 输出缓存最大长度
#define OPER1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER2 CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SYMBOLICLINK_NAME L"\\\\.\\MyTestDriver"

HANDLE g_hDriver; //驱动句柄


/*************************************************/
//打开驱动服务句柄
//3环链接名称： \\\\.\\AABB
/*************************************************/

void  __declspec(naked) NewMessageBox() {

	__asm {

		// 1 保存寄存器
		pushad
		pushfd

		int 3;

		// 2 修改数据： esp+8 
		LEA EAX, DWORD PTR DS : [szNewText]
		MOV DWORD PTR SS : [esp + 0x24 + 8] , EAX

		// 3 恢复寄存器
		popfd
		popad

		// 4 执行覆盖的代码
		MOV EDI, EDI
		PUSH EBP
		MOV EBP, ESP

		// 5 返回执行
		jmp dwRetAddress
	}

}

BOOL HookMessageBox(BOOL bOpen) {

	BOOL bRet = FALSE;
	BYTE byJmpCode[PATCH_LENGTH] = { 0xE9 };
	DWORD dwOldProtect = 0;

	static BYTE byOriginalCode[PATCH_LENGTH] = { 0 };
	static BOOL bHookFlag = FALSE;

	//1 初始化 byJmpCode
	memset(&byJmpCode[1], 0x90, PATCH_LENGTH - 1);

	//2 存储跳转地址
	*(DWORD*)&byJmpCode[1] = (DWORD)NewMessageBox - (DWORD)dwHookAddress - 5;

	//3 备份被覆盖的Code
	memcpy(byOriginalCode, (LPVOID)dwHookAddress, PATCH_LENGTH);

	// 4 开始 patch
	if (bOpen) {
		if (!bHookFlag) {
			VirtualProtect((LPVOID)dwHookAddress, PATCH_LENGTH, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((LPVOID)dwHookAddress, byJmpCode, PATCH_LENGTH);
			VirtualProtect((LPVOID)dwHookAddress, PATCH_LENGTH, dwOldProtect, 0);
			bHookFlag = TRUE;
			bRet = TRUE;
		}

	}
	else {

		if (bHookFlag) {

			VirtualProtect((LPVOID)dwHookAddress, PATCH_LENGTH, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((LPVOID)dwHookAddress, byOriginalCode, PATCH_LENGTH);
			VirtualProtect((LPVOID)dwHookAddress, PATCH_LENGTH, dwOldProtect, 0);
			bHookFlag = FALSE;
			bRet = TRUE;
		}

	}

	return bRet;
}

BOOL Open(PWCHAR pLinkName) {

	// 在3环获取驱动句柄
	TCHAR szBuffer[10] = { 0 };
	g_hDriver = ::CreateFile(pLinkName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD err = ::GetLastError();
	swprintf_s(szBuffer, L"%d\n", err);


	if (g_hDriver != INVALID_HANDLE_VALUE) {

		return TRUE;
	}
	else {

		return FALSE;

	}

}

BOOL IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen) {

	DWORD dw;
	//设备句柄/操作码/输入缓冲区地址/输入缓冲区长度/输出缓冲区地址/输出缓冲区长度/返回长度/指向OVERLAPPED此处为NULL
	DeviceIoControl(g_hDriver, dwIoCode, InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL);

	return TRUE;

}

int main(int argc, char* argv[])
{

	////////////////////////////////////MessageBox and ProcessId//////////////////////////////
	int* Inbuff = (int*)malloc(12);
	ZeroMemory(Inbuff, 12);

	//获取要 Hook 的函数地址 
	dwHookAddress = (DWORD)GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
	//获取进程 ID
	DWORD currentProcessID = GetCurrentProcessId();
	*Inbuff = dwHookAddress;
	DWORD value = *(PULONG)dwHookAddress;
	*(Inbuff + 1) = currentProcessID;

	printf("MessageBoxW address %08X\n", dwHookAddress);
	system("pause");
	TCHAR szOutBuffer[OUT_BUFFER_MAXLENGTH] = { 0 };

	//1 通过符号连接 打开设备
	Open((PWCHAR)SYMBOLICLINK_NAME);



	//2 测试通信
//	IoControl(OPER2,&dwInBuffer,IN_BUFFER_MAXLENGTH,szOutBuffer,OUT_BUFFER_MAXLENGTH);
	IoControl(OPER2, &Inbuff, IN_BUFFER_MAXLENGTH, szOutBuffer, OUT_BUFFER_MAXLENGTH);


	/////////////////////HOOK//////////////////
	//获取要 HOOK的函数地址
	dwRetAddress = dwHookAddress + PATCH_LENGTH;
	//安装或者卸载HOOK
	HookMessageBox(TRUE);

	MessageBox(0, 0, 0, 0);

	/////////////////////HOOK//////////////////

//	printf("%s",szOutBuffer);

	//3 关闭设备
	CloseHandle(g_hDriver);
	return 0;
}


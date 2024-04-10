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

char hookShellCode[25] = {
	0x60, 													//pushad
	0x9C, 													//pushfd
	0x36, 0xC7, 0x44, 0x24, 0x2C, 0x00, 0x00, 0x00, 0x00,   //mov         dword ptr ss:[esp+2Ch],0  index 7
	0x9D,                   								//popfd  
	0x61,													//popad
	0x8B, 0xFF,                								//mov         edi,edi  index 13
	0x55,													//push        ebp
	0x8B,0xEC ,               								//mov         ebp,esp
	0xB8 ,0,0,0,0,											//mov eax, retaddress  index 19
	0xFF,0xE0												//jmp eax
};
/*************************************************/
//打开驱动服务句柄
//3环链接名称： \\\\.\\AABB
/*************************************************/

BOOL HookMessageBox(BOOL bOpen,DWORD shellCodeAddr) {

	BOOL bRet = FALSE;
	BYTE byJmpCode[PATCH_LENGTH] = { 0xE9 };
	DWORD dwOldProtect = 0;

	static BYTE byOriginalCode[PATCH_LENGTH] = { 0 };
	static BOOL bHookFlag = FALSE;

	//1 初始化 byJmpCode
	memset(&byJmpCode[1], 0x90, PATCH_LENGTH - 1);

	//2 存储跳转地址
	*(DWORD*)&byJmpCode[1] = (DWORD)shellCodeAddr - (DWORD)dwHookAddress - 5;

	//3 备份被覆盖的Code
	memcpy(byOriginalCode, (LPVOID)dwHookAddress, PATCH_LENGTH);

	// 4 开始 patch
	memcpy((LPVOID)dwHookAddress, byJmpCode, PATCH_LENGTH);
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

void installHook()
{
	int* Inbuff = (int*)malloc(16);
	ZeroMemory(Inbuff, 16);

	//获取要 Hook 的函数地址 
	dwHookAddress = (DWORD)GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
	//获取进程 ID
	DWORD currentProcessID = GetCurrentProcessId();
	*Inbuff = dwHookAddress;
	DWORD value = *(PULONG)dwHookAddress;
	*(Inbuff + 1) = currentProcessID;


	printf("MessageBoxW address %08X\n", dwHookAddress);
	TCHAR szOutBuffer[OUT_BUFFER_MAXLENGTH] = { 0 };

	//1 通过符号连接 打开设备
	Open((PWCHAR)SYMBOLICLINK_NAME);


	//copy shell code 到user32 中空闲点
	DWORD shellAddress = dwHookAddress + 0x137C0;
	//访问下触发页异常
	value = *(PULONG)shellAddress;
	*(Inbuff + 2) = shellAddress;

	//2 测试通信
//	IoControl(OPER2,&dwInBuffer,IN_BUFFER_MAXLENGTH,szOutBuffer,OUT_BUFFER_MAXLENGTH);
	IoControl(OPER2, &Inbuff, IN_BUFFER_MAXLENGTH, szOutBuffer, OUT_BUFFER_MAXLENGTH);

	//获取要 HOOK的函数地址
	dwRetAddress = dwHookAddress + PATCH_LENGTH;
	*(PDWORD)&hookShellCode[19] = dwRetAddress;

	//文本地址
	DWORD textAddress = shellAddress + sizeof(hookShellCode) + 2;
	*(PDWORD)&hookShellCode[7] = textAddress;

	//copy shell 
	memcpy((PVOID)shellAddress, hookShellCode, sizeof(hookShellCode));

	printf("============copy one=================");

	//copy text "Inline Hook"
	TCHAR* pText = (TCHAR*)L"Inline Hook";
	memcpy((PVOID)textAddress, pText,24);

	printf("============copy two=================");


	//安装或者卸载HOOK
	HookMessageBox(TRUE, shellAddress);

	printf("============copy three=================");

	//test 
	MessageBox(0, L"111", L"222", 0);

	//3 关闭设备
	CloseHandle(g_hDriver);
}

void unloadHook()
{
	int* Inbuff = (int*)malloc(16);
	ZeroMemory(Inbuff, 16);

	//获取要 Hook 的函数地址 
	dwHookAddress = (DWORD)GetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
	//获取进程 ID
	DWORD currentProcessID = GetCurrentProcessId();
	*Inbuff = dwHookAddress;
	DWORD value = *(PULONG)dwHookAddress;
	*(Inbuff + 1) = currentProcessID;


	printf("MessageBoxW address %08X\n", dwHookAddress);
	TCHAR szOutBuffer[OUT_BUFFER_MAXLENGTH] = { 0 };

	//1 通过符号连接 打开设备
	Open((PWCHAR)SYMBOLICLINK_NAME);


	//copy shell code 到user32 中空闲点
	DWORD shellAddress = dwHookAddress + 0x137C0;
	//访问下触发页异常
	value = *(PULONG)shellAddress;
	*(Inbuff + 2) = shellAddress;

	IoControl(OPER2, &Inbuff, IN_BUFFER_MAXLENGTH, szOutBuffer, OUT_BUFFER_MAXLENGTH);
	memcpy((PVOID)dwHookAddress, &hookShellCode[13], 5);
	//3 关闭设备
	CloseHandle(g_hDriver);
}

int main(int argc, char* argv[])
{
	installHook();
	//unloadHook();
	return 0;
}


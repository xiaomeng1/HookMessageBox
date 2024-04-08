#include <ntifs.h>
#include <ntstatus.h>

//这个设备名 MyDevice是给 内核程序看的
#define DEVICE_NAME L"\\Device\\MyDevice"
//三环用CreateFile打开设备时，用 \\\\.\\MyTestDriver
//符号链接 在 0环 必须以 \\?? 开头
#define SYMBOLICLINK_NAME L"\\??\\MyTestDriver"


#define OPER1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER2 CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_ANY_ACCESS)

VOID DriverUnload(PDRIVER_OBJECT pDriver) {

	UNICODE_STRING SymbolicLinkName = { 0 };
	DbgPrint("启动程序停止了");

	//删除符号链接  删除设备
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLICLINK_NAME);
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(pDriver->DeviceObject);

}

//IRP_MJ_CREATE 处理函数
NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevOjb, PIRP pIrp) {

	DbgPrint("DispatchCreate ... \n");
	//返回状态如果 不设置 Ring3 返回的是失败
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//IRP_MJ_CLOSE 处理函数
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevOjb, PIRP pIrp) {
	DbgPrint("DispatchClose ...\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//设置页属性
void setPageRW(DWORD_PTR address)
{
	ULONG dwAddr = address;
	ULONG PDE = 0xc0300000 + ((dwAddr >> 20) & 0xFFC);        //-----------------0           
	ULONG PTE = 0xC0000000 + ((dwAddr >> 10) & 0x3FFFFC);  //------------------0x20          

	__asm {
		push eax;
		push ebx;

		mov eax, [PDE];
		mov ebx, [eax];
		or ebx, 0x02; //修改 PDE 读写位
		mov[eax], ebx;

		mov eax, [PTE];
		mov ebx, [eax];
		test ebx, ebx;
		jz _exit;
		or ebx, 0x02; //修改 PDE 读写位
		mov[eax], ebx;
	_exit:
		pop ebx;
		pop eax;
	}
}


//IRP_MJ_DEVIDE_CONTROL 处理函数 用来处理 Ring3交互
NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevOjb, PIRP pIrp) {

	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInLength;
	ULONG uOutLength;
	ULONG uRead;
	ULONG uReadOne;
	ULONG uWrite;

	uRead = 0;
	uWrite = 0x12345678;

	//获取IRP数据
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	//获取控制码
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//获取缓冲区地址(输入和输出的缓冲区都是一个)
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	//Ring 3 发送数据的长度
	uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//Ring 0 发送数据的长度
	uOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode) {

	case OPER1:
	{
		DbgPrint("IrpDeviceControlProc-> OPER1 ...\n");
		pIrp->IoStatus.Information = 0;
		status = STATUS_SUCCESS;;
		break;
	}
	case OPER2:
	{
		DbgPrint("IrpDeviceControlProc -> OPER2 接收字节数: %d \n", uInLength);
		DbgPrint("IrpDeviceControlProc -> OPER2 输出字节数: %d \n", uOutLength);


		PULONG* messageBox = ((ULONG)pIoBuffer);
		ULONG messageBoxValue = *messageBox;
		PULONG* messageBoxAddress = messageBoxValue;
		ULONG messageBoxAddress_ture = *messageBoxAddress;

		ULONG currentProcessID = *(messageBoxAddress + 1);
		ULONG shellCodeAddress = *(messageBoxAddress + 2);

		HANDLE processId = (HANDLE)currentProcessID; // 获取当前进程的ID-----写拷贝 三环传传过来的 进程 ID

		PEPROCESS process = NULL;

		NTSTATUS status = PsLookupProcessByProcessId(processId, &process); // 通过ID获取PEPROCESS结构体

		KAPC_STATE  ApcState;

		DbgBreakPoint();

		if (process != NULL) {
			KeStackAttachProcess(process, &ApcState);

			//messagebox 
			setPageRW(messageBoxAddress_ture);
			//shellccode
			setPageRW(shellCodeAddress);
			// 不再需要时，必须释放PEPROCESS结构体
			ObDereferenceObject(process);
		}

		///////////////////////////////////////////////

		//Write To Buffer
		memcpy(pIoBuffer, &uWrite, 4);
		//Set Status

		pIrp->IoStatus.Information = 4;
		status = STATUS_SUCCESS;
		break;
	}
	}

	//设置返回状态
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg) {
	//	DbgBreakPoint();

	NTSTATUS status = 0;
	ULONG uIndex = 0;
	PDEVICE_OBJECT pDeviceObj = NULL;
	UNICODE_STRING Devicename;
	UNICODE_STRING SymbolicLinkName;

	//创建设备名称
	RtlInitUnicodeString(&Devicename, DEVICE_NAME);

	//创建设备
	status = IoCreateDevice(pDriver, 0, &Devicename, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if (status != STATUS_SUCCESS) {

		DbgPrint("创建设备失败! \r\n");
		return status;
	}

	//设置交互数据的方式
	pDeviceObj->Flags |= DO_BUFFERED_IO;

	//创建符号链接名称
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLICLINK_NAME);

	//创建符号链接(创建当前设备的别名)------------这个符号链接 是给 三环的程序看的
	//想要让 三环的程序找到 ，必须创建一个 符号链接
	status = IoCreateSymbolicLink(&SymbolicLinkName, &Devicename);

	if (status != STATUS_SUCCESS) {

		DbgPrint("创建符号链接失败！ \r\n");
		IoDeleteDevice(pDeviceObj);
		return status;
	}

	//设置分发函数和卸载函数
	pDriver->MajorFunction[IRP_MJ_CREATE] = IrpCreateProc;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = IrpCloseProc;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlProc;
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;

}
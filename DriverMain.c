#include <ntifs.h>
#include <ntstatus.h>

//����豸�� MyDevice�Ǹ� �ں˳��򿴵�
#define DEVICE_NAME L"\\Device\\MyDevice"
//������CreateFile���豸ʱ���� \\\\.\\MyTestDriver
//�������� �� 0�� ������ \\?? ��ͷ
#define SYMBOLICLINK_NAME L"\\??\\MyTestDriver"


#define OPER1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER2 CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_ANY_ACCESS)

VOID DriverUnload(PDRIVER_OBJECT pDriver) {

	UNICODE_STRING SymbolicLinkName = { 0 };
	DbgPrint("��������ֹͣ��");

	//ɾ����������  ɾ���豸
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLICLINK_NAME);
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(pDriver->DeviceObject);

}

//IRP_MJ_CREATE ������
NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevOjb, PIRP pIrp) {

	DbgPrint("DispatchCreate ... \n");
	//����״̬��� ������ Ring3 ���ص���ʧ��
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//IRP_MJ_CLOSE ������
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevOjb, PIRP pIrp) {
	DbgPrint("DispatchClose ...\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//����ҳ����
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
		or ebx, 0x02; //�޸� PDE ��дλ
		mov[eax], ebx;

		mov eax, [PTE];
		mov ebx, [eax];
		test ebx, ebx;
		jz _exit;
		or ebx, 0x02; //�޸� PDE ��дλ
		mov[eax], ebx;
	_exit:
		pop ebx;
		pop eax;
	}
}


//IRP_MJ_DEVIDE_CONTROL ������ �������� Ring3����
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

	//��ȡIRP����
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	//��ȡ������
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//��ȡ��������ַ(���������Ļ���������һ��)
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	//Ring 3 �������ݵĳ���
	uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//Ring 0 �������ݵĳ���
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
		DbgPrint("IrpDeviceControlProc -> OPER2 �����ֽ���: %d \n", uInLength);
		DbgPrint("IrpDeviceControlProc -> OPER2 ����ֽ���: %d \n", uOutLength);


		PULONG* messageBox = ((ULONG)pIoBuffer);
		ULONG messageBoxValue = *messageBox;
		PULONG* messageBoxAddress = messageBoxValue;
		ULONG messageBoxAddress_ture = *messageBoxAddress;

		ULONG currentProcessID = *(messageBoxAddress + 1);
		ULONG shellCodeAddress = *(messageBoxAddress + 2);

		HANDLE processId = (HANDLE)currentProcessID; // ��ȡ��ǰ���̵�ID-----д���� �������������� ���� ID

		PEPROCESS process = NULL;

		NTSTATUS status = PsLookupProcessByProcessId(processId, &process); // ͨ��ID��ȡPEPROCESS�ṹ��

		KAPC_STATE  ApcState;

		DbgBreakPoint();

		if (process != NULL) {
			KeStackAttachProcess(process, &ApcState);

			//messagebox 
			setPageRW(messageBoxAddress_ture);
			//shellccode
			setPageRW(shellCodeAddress);
			// ������Ҫʱ�������ͷ�PEPROCESS�ṹ��
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

	//���÷���״̬
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

	//�����豸����
	RtlInitUnicodeString(&Devicename, DEVICE_NAME);

	//�����豸
	status = IoCreateDevice(pDriver, 0, &Devicename, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if (status != STATUS_SUCCESS) {

		DbgPrint("�����豸ʧ��! \r\n");
		return status;
	}

	//���ý������ݵķ�ʽ
	pDeviceObj->Flags |= DO_BUFFERED_IO;

	//����������������
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLICLINK_NAME);

	//������������(������ǰ�豸�ı���)------------����������� �Ǹ� �����ĳ��򿴵�
	//��Ҫ�� �����ĳ����ҵ� �����봴��һ�� ��������
	status = IoCreateSymbolicLink(&SymbolicLinkName, &Devicename);

	if (status != STATUS_SUCCESS) {

		DbgPrint("������������ʧ�ܣ� \r\n");
		IoDeleteDevice(pDeviceObj);
		return status;
	}

	//���÷ַ�������ж�غ���
	pDriver->MajorFunction[IRP_MJ_CREATE] = IrpCreateProc;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = IrpCloseProc;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlProc;
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;

}
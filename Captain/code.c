#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

//Driver DIspatch call back function, return type -> STATUS_SUCCESS; takes Device object and *IRP as parameters)
DRIVER_DISPATCH CustomIOCTL;

/*Defining I/O Control codes; 
Format: #define IOCTL_DEVICE_FUNCTION CTL_CODE(DeviceType, Function, Method, Access)*/

#define IOCTL_CAPTAIN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x00000022, METHOD_BUFFERED, FILE_ANY_ACCESS)
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\CaptainDevice");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\CaptainDevice");

void CreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	if (create)
	{
		PEPROCESS process = NULL;
		PUNICODE_STRING parentProcessName = NULL, processName = NULL;

		PsLookupProcessByProcessId(ppid, &process);
		SeLocateProcessImageName(process, &parentProcessName);

		PsLookupProcessByProcessId(pid, &process);
		SeLocateProcessImageName(process, &processName);

		DbgPrint("%d %wZ\n\t\t%d %wZ", ppid, parentProcessName, pid, processName);
	}
	else
	{
		DbgPrint("Process %d lost child %d", ppid, pid);
	}
}

void CreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)

{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(pid);

	if (createInfo != NULL)
	{
		if (wcsstr(createInfo->CommandLine->Buffer, L"notepad") != NULL)
		{
			DbgPrint("[!] Access to launch notepad.exe was denied!");
			createInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}
	}
}

void LoadImageNotifyRoutine(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
	UNREFERENCED_PARAMETER(imageInfo);
	PEPROCESS process = NULL;
	PUNICODE_STRING processName = NULL;
	PsLookupProcessByProcessId(pid, &process);
	SeLocateProcessImageName(process, &processName);

	DbgPrint("%wZ (%d) loaded %wZ", processName, pid, imageName);
}

void CreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create)
{
	if (create)
	{
		DbgPrint("%d created thread %d", pid, tid);
	}
	else
	{
		DbgPrint("Thread %d of process %d exited", tid, pid);
	}
}


NTSTATUS MajorFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (stackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrint("Handle to symbolink link %wZ opened", DEVICE_SYMBOLIC_NAME);
		break;
	case IRP_MJ_CLOSE:
		DbgPrint("Handle to symbolink link %wZ closed", DEVICE_SYMBOLIC_NAME);
		break;
	default:
		break;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS CustomIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	CHAR* messageFromKernel = "ohai from them kernelz";

	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_CAPTAIN)
	{
		DbgPrint("IOCTL_SPOTLESS (0x%x) issued", stackLocation->Parameters.DeviceIoControl.IoControlCode);
		DbgPrint("Input received from userland: %s", (char*)Irp->AssociatedIrp.SystemBuffer);
	}

	Irp->IoStatus.Information = strlen(messageFromKernel);
	Irp->IoStatus.Status = STATUS_SUCCESS;

	DbgPrint("Sending to userland: %s", messageFromKernel);
	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, messageFromKernel, strlen(Irp->AssociatedIrp.SystemBuffer));

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;

	//Routine for handling IO req from higher level, IRP_MJ_DEVICE_CONTROL
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CustomIOCTL;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CustomIOCTL;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CustomIOCTL;

	DbgPrint("Driver loaded");

	PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE);
	DbgPrint("Listeners isntalled..");

	IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create device %wZ", DEVICE_NAME);
	}
	else
	{
		DbgPrint("Device %wZ created", DEVICE_NAME);
	}

	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
	if (NT_SUCCESS(status))
	{
		DbgPrint("Symbolic link %wZ created", DEVICE_SYMBOLIC_NAME);
	}
	else
	{
		DbgPrint("Error creating symbolic link %wZ", DEVICE_SYMBOLIC_NAME);
	}

	return STATUS_SUCCESS;
}
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

//Driver DIspatch call back function, return type -> STATUS_SUCCESS; takes Device object and *IRP as parameters)
DRIVER_DISPATCH CustomIOCTL;

/*Defining I/O Control codes;
Format: #define IOCTL_DEVICE_FUNCTION CTL_CODE(DeviceType, Function, Method, Access)*/

#define IOCTL_CAPTAIN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x00000822, METHOD_BUFFERED, FILE_ANY_ACCESS)
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\CaptainDevice");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\CaptainDevice");
UNICODE_STRING NULL_STR = RTL_CONSTANT_STRING(L"<NULL>");

// Bypass HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter
#define DbgPrint(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Captain] " format "\n", __VA_ARGS__)

PUNICODE_STRING SafeString(PUNICODE_STRING str)
{
	return str != NULL ? str : &NULL_STR;
}

PUNICODE_STRING GetImageName(HANDLE pid)
{
	PUNICODE_STRING processName = NULL;
	PEPROCESS process = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
	{
		if (!NT_SUCCESS(SeLocateProcessImageName(process, &processName)))
		{
			processName = NULL;
		}
		ObDereferenceObject(process);
	}
	return processName;
}

void CreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	if (create)
	{
		PUNICODE_STRING parentProcessName = GetImageName(ppid);
		PUNICODE_STRING processName = GetImageName(pid);

		DbgPrint("%wZ (%u) created %wZ (%d)", SafeString(parentProcessName), ppid, SafeString(processName), pid);

		if (processName != NULL)
		{
			ExFreePool(processName);
		}

		if (parentProcessName != NULL)
		{
			ExFreePool(parentProcessName);
		}
	}
	else
	{
		DbgPrint("Process %u lost child %u", ppid, pid);
	}
}

void LoadImageNotifyRoutine(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
	UNREFERENCED_PARAMETER(imageInfo);

	PUNICODE_STRING processName = GetImageName(pid);

	DbgPrint("%wZ (%u) loaded %wZ", SafeString(processName), pid, imageName);

	if (processName != NULL)
	{
		ExFreePool(processName);
	}
}

void CreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create)
{
	if (create)
	{
		DbgPrint("%u created thread %u", pid, tid);
	}
	else
	{
		DbgPrint("Thread %u of process %u exited", tid, pid);
	}
}

void CreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(pid);

	if (createInfo != NULL)
	{
		PCUNICODE_STRING commandLine = createInfo->CommandLine;
		if (commandLine != NULL && wcsstr(commandLine->Buffer, L"notepad") != NULL)
		{
			DbgPrint("[!] Access to launch notepad.exe was denied!");
			createInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}
	}
}

NTSTATUS DeviceCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
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

NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stackLocation = NULL;
	CHAR* messageFromKernel = "ohai from them kernelz";

	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (stackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_CAPTAIN:
	{
		DbgPrint("IOCTL_CAPTAIN (0x%x) issued", stackLocation->Parameters.DeviceIoControl.IoControlCode);

		// Make sure to not read beyond the SystemBuffer
		char* systemBuffer = (char*)Irp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG stringLength = (ULONG)strnlen_s(systemBuffer, inputLength);
		DbgPrint("Input received from userland: %.*s", stringLength, systemBuffer);

		// Amount of space (required) in the output buffer
		Irp->IoStatus.Information = strlen(messageFromKernel) + 1;

		// Make sure there is enough space in the output buffer
		if (stackLocation->Parameters.DeviceIoControl.OutputBufferLength > strlen(messageFromKernel))
		{
			DbgPrint("Sending to userland: %s", messageFromKernel);

			strcpy(systemBuffer, messageFromKernel);

			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("Buffer not big enough!");

			Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		}
	}
	break;

	default:
	{
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	}
	break;
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
	IoDeleteDevice(DriverObject->DeviceObject);

	PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, TRUE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("Driver loaded");

	PDEVICE_OBJECT deviceObject = NULL;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create device %wZ (status: 0x%08X)", DEVICE_NAME, status);
		return status;
	}
	else
	{
		DbgPrint("Device %wZ created", DEVICE_NAME);
	}

	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(deviceObject);
		DbgPrint("Error creating symbolic link %wZ (status: 0x%08X)", DEVICE_SYMBOLIC_NAME, status);
		return status;
	}
	else
	{
		DbgPrint("Symbolic link %wZ created", DEVICE_SYMBOLIC_NAME);
	}

	// Set IRP routines
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
	DriverObject->DriverUnload = DriverUnload;

	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/clearing-the-do-device-initializing-flag
	ClearFlag(deviceObject->Flags, DO_DEVICE_INITIALIZING);

	status = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsSetCreateProcessNotifyRoutine failed (status 0x%08X)", status);
	}

	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsSetLoadImageNotifyRoutine failed (status 0x%08X)", status);
	}

	status = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsSetCreateThreadNotifyRoutine failed (status 0x%08X)", status);
	}

	// You need IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY for this callback
	status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsSetCreateProcessNotifyRoutineEx failed (status 0x%08X)", status);
	}
	DbgPrint("Listeners installed...");

	return STATUS_SUCCESS;
}
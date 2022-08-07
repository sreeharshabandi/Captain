# Windows_Device_Driver Captain

This can be used to subscribe for Process creation, Tread creation and Image Load notification from a kernel Driver.

PsCreateProcessNotifyRoutine, PsSetLoadImageNotifyRoutine and PsSetCreateThreadNotifyRoutine Functions are used to add a driver-supplied callback routine to a list of routiens to be called whenever a process is created or deleted, Image is loded and Thread is created or deleted.

In this post we will be looking at my recent develpment, <strong>Windows kernel driver - [Captain][linktocaptain].</strong>

<strong> Prior knowledge on the following topics are required: </strong>
1. <code class="highlighter-rouge">Device I/O Control function.</code>
2. <code class="highlighter-rouge">Defining new IOCTL codes.</code>
3. <code class="highlighter-rouge">Usage of Windows Driver Framework.</code>
4. <code class="highlighter-rouge">Kernel-mode call-back routines.</code>

```c++
if(fail to have the above required knowledge)
{
    printf("Don't worry, you can learn that in this post:")
}
```

<p><strong> <code class="highlighter-rouge"> Device I/O Control function: </code></strong></p>
<p>The DeviceIoControl function provides a interface for an application to communicate with the device driver, and can send control codes to a variety of devices. </p>

![alt text](https://github.com/sreeharshabandi/images/blob/main/ioclt.jpg)

Control codes can be specified depending on the device being used.

The syntax for the DeviceIoControl Function is shown below:

``` c++
BOOL DeviceIoControl(
  HANDLE       hDevice,
  DWORD        dwIoControlCode,
  LPVOID       lpInBuffer,
  DWORD        nInBufferSize,
  LPVOID       lpOutBuffer,
  DWORD        nOutBufferSize,
  LPDWORD      lpBytesReturned,
  LPOVERLAPPED lpOverlapped
);
```
Information related to its parameters can be found [here][IOCTL_syntax].


<p><strong> <code class="highlighter-rouge"> Defing New IOCTL code's: </code></strong></p>

An IO Control code is a 32-bit value that consist of following fields:
1. Transfer type.
2. Function code.
3. Custom.
4. Required Access.
5. Device type.
6. Common.

IRP_MJ_DEVICE_CONTROL should be used for user-mode software coponents.
IRP_MJ_INTERNAL_DEVICE_CONTROL should be used for kernel-mode components. 

CTL_CODE macro is System-supplied and is defined in Wdm.h and Ntddk.h

Format for defining new I/O control code:

``` c++
define IOCTL_Device_Function CTL_CODE(DeviceType, Function, Method, Access)
```
Example for Captain:
``` c++
define IOCTL_Captain CTL_CODE(FILE_DEVICE_UNKNOWN, 0x00000822, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Details related to Devicetype, Function, Method and Access can be found [here][define_control].


<p><strong> <code class="highlighter-rouge"> Kernel-mode call-back routines: </code></strong></p>

Windows contains a wide variety of kernel-mode callback routines that driver developers can opt into to receive various event notifications. Below are few callback routines that I have used during the development of Captain.
1. PsSetCreateProcessNotifyRoutine.
2. PsSetLoadImageNotifyRoutine.
3. PsSetLoadImageNotifyRoutineEx.
3. PsSetCreateThreadNotifyRoutine.
4. PsSetCreateThreadNotifyRoutineEx.

Callbacks can be used by driver developers to gain notifications when certain events happen. For example, the basic process creation callback, PsSetCreateProcessNotifyRoutine, registers a user-defined function pointer ("NotifyRoutine") that will be invoked by Windows each time a process is created or deleted.

Syntax for the above mentioned callbacks are as below:

```c++
NTSTATUS PsSetCreateProcessNotifyRoutine(
  PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
  BOOLEAN                        Remove
);
```
```c++
NTSTATUS PsSetLoadImageNotifyRoutine(
  PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);
```
```c++
NTSTATUS PsSetLoadImageNotifyRoutineEx(
  PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
  ULONG_PTR                  Flags
);
```
```c++
NTSTATUS PsSetCreateThreadNotifyRoutine(
  PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);
```
```c++
NTSTATUS PsSetCreateThreadNotifyRoutineEx(
  PSCREATETHREADNOTIFYTYPE NotifyType,
  PVOID                    NotifyInformation
);
```
<p>Two return values for the above mentioned callbacks:</P>
1. STATUS_SUCCESS
2. STATUS_INSUFFICIENT_RESOURCES

<p><strong>Thanks For Reading.</strong></p>

[IOCTL_syntax]: https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol?redirectedfrom=MSDN 
[define_control]:https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes#:~:text=%20When%20defining%20new%20IOCTLs%2C%20it%20is%20important,the%20IOCTL%20must%20be%20used%20with...%20More%20
[linktocaptain]: https://github.com/sreeharshabandi/Captain


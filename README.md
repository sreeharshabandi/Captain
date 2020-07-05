# Windows_Device_Driver Captain

This can be used to subscribe for Process creation, Tread creation and Image Load notification from a kernel Driver.

PsCreateProcessNotifyRoutine, PsSetLoadImageNotifyRoutine and PsSetCreateThreadNotifyRoutine Functions are used to add a driver-supplied callback routine to a list of routiens to be called whenever a process is created or deleted, Image is loded and Thread is created or deleted.

Detailed explanation can be found Here <href>https://sreeharshabandi.github.io</href>

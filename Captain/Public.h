/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_Captain,
    0x9cb24046,0x9927,0x4925,0xa0,0xe1,0xed,0x99,0x82,0xe8,0xf5,0xfc);
// {9cb24046-9927-4925-a0e1-ed9982e8f5fc}

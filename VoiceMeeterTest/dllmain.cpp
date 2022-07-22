#include "pch.h"
#include <iostream>
#include "templates.h"


// Make sure DLL name is Mfplat.dll;


uintptr_t BaseAddress;
bool debug = false;


DWORD WINAPI PatchThread(LPVOID) {
   unsigned long RefProt;

   iterable_queue<uintptr_t> arr;

    arr.push((uintptr_t)BaseAddress + 0xD680A);
    arr.push((uintptr_t)BaseAddress + 0xD5D5D);
    arr.push((uintptr_t)BaseAddress + 0xD5D66);
    arr.push((uintptr_t)BaseAddress + 0xD66CA);
    arr.push((uintptr_t)BaseAddress + 0xD66D7);


    for (auto bytarrnum = arr.begin(); bytarrnum != arr.end(); ++bytarrnum)
    {
        std::cout << "Patched:  " << "0x" << std::hex << *bytarrnum << std::endl;
        char byts[] = "\x83\x3D\x9B\x00\x20\x00\x01";
        // Turns out it was protected changing entitlements and then setting the old entitlements back after the patch.
        VirtualProtect((LPVOID)((uintptr_t)*bytarrnum), 7, PAGE_EXECUTE_READWRITE, &RefProt);
        memcpy((LPVOID)*bytarrnum, byts, 7);
        VirtualProtect((LPVOID)(*bytarrnum), 7, RefProt, NULL);
    }

    // Applies Patch which makes it seem like you are activated already when you try to activate.
    uintptr_t CongAddy = BaseAddress + 0x10E71;
    char congbts[] = "\x83\xB8\xF0\x0C\x00\x00\x00";
    VirtualProtect((LPVOID)((uintptr_t)CongAddy), 7, PAGE_EXECUTE_READWRITE, &RefProt);
    memcpy((LPVOID)(uintptr_t)CongAddy, congbts, 7);
    VirtualProtect((LPVOID)(CongAddy), 7, RefProt, NULL);

    return 0;
}


DWORD WINAPI MainThread(LPVOID) 
{
    if (debug)
    {
        AllocConsole();
        FILE* pFile;
        freopen_s(&pFile, "CONOUT$", "w", stdout);
    }
    BaseAddress = reinterpret_cast<uintptr_t>(GetModuleHandle(0));

    CreateThread(0, 0, PatchThread, 0, 0, 0);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID res)
{
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(0, 0, MainThread, mod, 0, 0);

    return TRUE;
}
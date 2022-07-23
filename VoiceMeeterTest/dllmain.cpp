#pragma once
#include "pch.h"
#include <iostream>
#include "templates.h"
#include "mem.h"



// Make sure DLL name is Mfplat.dll;


bool debug = true;
unsigned long RefProt;
iterable_queue<uintptr_t> arr;




DWORD WINAPI PatchThread(LPVOID) 
{
    arr.push((uintptr_t)mem::FindPattern("83 3D 9B 00 20 00 00"));
    arr.push((uintptr_t)mem::FindPattern("44 39 2D 48 0B 20 00"));
    arr.push((uintptr_t)mem::FindPattern("44 39 2D 43 0B 20 00"));
    arr.push((uintptr_t)mem::FindPattern("44 39 2D DB 01 20 00"));
    arr.push((uintptr_t)mem::FindPattern("44 39 2D D2 01 20 00"));
    for (auto bytarrnum = arr.begin(); bytarrnum != arr.end(); ++bytarrnum)
    {
        std::cout << "Patched:  " << "0x" << std::hex << *bytarrnum << std::endl;
        char byts[] = "\x83\x3D\x9B\x00\x20\x00\x01"; // cmp DWORD PTR [rip+0x20009b],0x1
        // Turns out it was protected (changed entitlements and then setting the old entitlements back after the patch.)
        VirtualProtect((LPVOID)((uintptr_t)*bytarrnum), 7, PAGE_EXECUTE_READWRITE, &RefProt);
        memcpy((LPVOID)*bytarrnum, byts, 7);
        VirtualProtect((LPVOID)(*bytarrnum), 7, RefProt, NULL);
    }
    // Applies Patch which makes it seem like you are activated already when you try to activate.
    uintptr_t CongAddy = mem::FindPattern("83 B8 F0 0C 00 00 01");
    char congbts[] = "\x83\xB8\xF0\x0C\x00\x00\x00"; //cmp DWORD PTR [rax+0xcf0],0x0
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
    CreateThread(0, 0, PatchThread, 0, 0, 0);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID res)
{
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(0, 0, MainThread, mod, 0, 0);

    return TRUE;
}
#include <windows.h>
#include <iostream>
#include <vector>
#include <expected>
#include <string>
#include <string_view>
#include <span>
#include <array>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DllEntryPoint = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
using f_RtlAddFunctionTable = BOOL(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

struct MAPPING_DATA {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    f_RtlAddFunctionTable pRtlAddFunctionTable;
    std::byte* pBase;
    HINSTANCE hModule;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
};

#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma code_seg(".shell")
void __stdcall Shellcode(MAPPING_DATA* pData) {
    auto* pBase = reinterpret_cast<uint8_t*>(pData->pBase);
    auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
    auto* pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);
    auto* pOptHeader = &pOldNtHeader->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
    auto _DllMain = reinterpret_cast<f_DllEntryPoint>(pBase + pOptHeader->AddressOfEntryPoint);

    bool _ExceptionSupportFailed = false;

    uint8_t* LocationDelta = pBase - pOptHeader->ImageBase;
    if (LocationDelta && pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
            uint32_t amountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            uint16_t* pRelativeInfo = reinterpret_cast<uint16_t*>(pRelocData + 1);

            for (uint32_t i = 0; i != amountOfEntries; ++i, ++pRelativeInfo) {
                if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_DIR64) {
                    auto* pPatch = reinterpret_cast<uintptr_t*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                    *pPatch += reinterpret_cast<uintptr_t>(LocationDelta);
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }

    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDesc->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            auto* pThunkRef = reinterpret_cast<uintptr_t*>(pBase + (pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk));
            auto* pFuncRef = reinterpret_cast<uintptr_t*>(pBase + pImportDesc->FirstThunk);

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = reinterpret_cast<uintptr_t>(_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
                } else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = reinterpret_cast<uintptr_t>(_GetProcAddress(hDll, pImport->Name));
                }
            }
            ++pImportDesc;
        }
    }

    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTls->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback) {
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    const auto& entryExcept = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (entryExcept.Size) {
        if (!_RtlAddFunctionTable(reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + entryExcept.VirtualAddress), entryExcept.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<DWORD64>(pBase))) {
            _ExceptionSupportFailed = true;
        }
    }

    _DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

    pData->hModule = _ExceptionSupportFailed ? reinterpret_cast<HINSTANCE>(0x505050) : reinterpret_cast<HINSTANCE>(pBase);
}

void __stdcall ShellcodeEnd() {}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.shell,ERW")
#pragma runtime_checks("", restore)
#pragma optimize("", on)

using MapResult = std::expected<bool, std::string>;

MapResult MapDll(HANDLE hProcess, std::span<const std::byte> dllBytes) {
    if (dllBytes.empty()) return std::unexpected("Empty DLL buffer");

    const auto* pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBytes.data());
    const auto* pOldNtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(dllBytes.data() + pDosHeader->e_lfanew);
    const auto* pOldOptHeader = &pOldNtHeader->OptionalHeader;
    const auto* pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
        return std::unexpected("Invalid platform! Only x64 is supported.");
    }

    auto* pTargetBase = static_cast<std::byte*>(VirtualAllocEx(hProcess, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase) {
        return std::unexpected("Target process memory allocation failed!");
    }

    DWORD oldProtect = 0;
    VirtualProtectEx(hProcess, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

    MAPPING_DATA data {
        .pLoadLibraryA = LoadLibraryA,
        .pGetProcAddress = GetProcAddress,
        .pRtlAddFunctionTable = reinterpret_cast<f_RtlAddFunctionTable>(RtlAddFunctionTable),
        .pBase = pTargetBase,
        .fdwReasonParam = DLL_PROCESS_ATTACH,
        .reservedParam = nullptr
    };

    if (!WriteProcessMemory(hProcess, pTargetBase, dllBytes.data(), 0x1000, nullptr)) {
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return std::unexpected("Failed to write PE header!");
    }

    auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, dllBytes.data() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
                return std::unexpected("Failed to map sections!");
            }
        }
    }

    auto* MappingDataAlloc = static_cast<std::byte*>(VirtualAllocEx(hProcess, nullptr, sizeof(MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!MappingDataAlloc || !WriteProcessMemory(hProcess, MappingDataAlloc, &data, sizeof(MAPPING_DATA), nullptr)) {
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return std::unexpected("Failed to write mapping data!");
    }

    const size_t shellcodeSize = reinterpret_cast<uintptr_t>(ShellcodeEnd) - reinterpret_cast<uintptr_t>(Shellcode);
    
    auto* pShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode || !WriteProcessMemory(hProcess, pShellcode, reinterpret_cast<LPCVOID>(Shellcode), shellcodeSize, nullptr)) {
        return std::unexpected("Failed to allocate or write shellcode!");
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
    if (!hThread) {
        return std::unexpected("Thread creation failed!");
    }
    CloseHandle(hThread);

    HINSTANCE hChecked = nullptr;
    while (!hChecked) {
        DWORD exitCode = 0;
        GetExitCodeProcess(hProcess, &exitCode);
        if (exitCode != STILL_ACTIVE) return std::unexpected("Process crashed!");

        MAPPING_DATA dataChecked{};
        ReadProcessMemory(hProcess, MappingDataAlloc, &dataChecked, sizeof(dataChecked), nullptr);
        hChecked = dataChecked.hModule;

        if (hChecked == reinterpret_cast<HINSTANCE>(0x404040)) return std::unexpected("Wrong mapping ptr!");
        if (hChecked == reinterpret_cast<HINSTANCE>(0x505050)) return std::unexpected("Exception support failed!");

        Sleep(5);
    }

    std::array<std::byte, 0x1000> emptyBuffer{};
    WriteProcessMemory(hProcess, pTargetBase, emptyBuffer.data(), 0x1000, nullptr);

    pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->Misc.VirtualSize) {
            DWORD newProtect = PAGE_READONLY;
            if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) newProtect = PAGE_READWRITE;
            else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) newProtect = PAGE_EXECUTE_READ;

            VirtualProtectEx(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newProtect, &oldProtect);
        }
    }

    WriteProcessMemory(hProcess, pShellcode, emptyBuffer.data(), shellcodeSize, nullptr);
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, MappingDataAlloc, 0, MEM_RELEASE);

    return true;
}

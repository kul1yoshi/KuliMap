#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <expected>
#include <string>
#include <string_view>
#include <span>
#include <array>
#include <memory>
#include <bit>

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
extern "C" void __stdcall Shellcode(MAPPING_DATA* pData) {
    if (!pData) return;

    auto* pBase = pData->pBase;
    auto* pDosHeader = std::bit_cast<IMAGE_DOS_HEADER*>(pBase);
    auto* pNtHeader = std::bit_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);
    auto* pOptHeader = &pNtHeader->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;

    auto delta = std::bit_cast<uintptr_t>(pBase) - pOptHeader->ImageBase;
    if (delta) {
        auto* pRelocDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDir->Size) {
            auto* pRelocData = std::bit_cast<IMAGE_BASE_RELOCATION*>(pBase + pRelocDir->VirtualAddress);
            while (pRelocData->VirtualAddress) {
                uint32_t entriesCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                uint16_t* pRelativeInfo = std::bit_cast<uint16_t*>(pRelocData + 1);

                for (uint32_t i = 0; i < entriesCount; ++i) {
                    if ((pRelativeInfo[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        auto* pPatch = std::bit_cast<uintptr_t*>(pBase + pRelocData->VirtualAddress + (pRelativeInfo[i] & 0xFFF));
                        *pPatch += delta;
                    }
                }

                pRelocData = std::bit_cast<IMAGE_BASE_RELOCATION*>(std::bit_cast<std::byte*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }

    auto* pImportDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size) {
        auto* pImportDesc = std::bit_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pImportDir->VirtualAddress);
        while (pImportDesc->Name) {
            HINSTANCE hDll = _LoadLibraryA(std::bit_cast<char*>(pBase + pImportDesc->Name));
            if (hDll) {
                auto* pThunkRef = std::bit_cast<uintptr_t*>(pBase + (pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk));
                auto* pFuncRef = std::bit_cast<uintptr_t*>(pBase + pImportDesc->FirstThunk);

                for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                    if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                        *pFuncRef = std::bit_cast<uintptr_t>(_GetProcAddress(hDll, std::bit_cast<char*>(*pThunkRef & 0xFFFF)));
                    }
                    else {
                        auto* pImport = std::bit_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                        *pFuncRef = std::bit_cast<uintptr_t>(_GetProcAddress(hDll, pImport->Name));
                    }
                }
            }
            ++pImportDesc;
        }
    }

    auto* pTlsDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (pTlsDir->Size) {
        auto* pTls = std::bit_cast<IMAGE_TLS_DIRECTORY*>(pBase + pTlsDir->VirtualAddress);
        auto* pCallback = std::bit_cast<PIMAGE_TLS_CALLBACK*>(pTls->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback) {
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    auto* pExceptDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pExceptDir->Size && _RtlAddFunctionTable) {
        auto* pFuncEntry = std::bit_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + pExceptDir->VirtualAddress);
        DWORD count = pExceptDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        _RtlAddFunctionTable(pFuncEntry, count, std::bit_cast<DWORD64>(pBase));
    }

    if (pOptHeader->AddressOfEntryPoint) {
        auto _DllMain = std::bit_cast<f_DllEntryPoint>(pBase + pOptHeader->AddressOfEntryPoint);
        _DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);
    }

    pData->hModule = std::bit_cast<HINSTANCE>(pBase);
}
extern "C" void __stdcall ShellcodeEnd() {}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.shell,ERW")
#pragma runtime_checks("", restore)
#pragma optimize("", on)

struct HandleDeleter {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
struct RemoteMemDeleter {
    HANDLE hProcess;
    void operator()(void* ptr) const {
        if (ptr) VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);
    }
};
using MapResult = std::expected<void, std::string>;
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;
using UniqueRemoteMem = std::unique_ptr<void, RemoteMemDeleter>;

MapResult MapDll(HANDLE hProcess, std::span<const std::byte> dllBytes) {
    if (dllBytes.empty()) return std::unexpected("DLL buffer is empty");

    auto* pDosHeader = std::bit_cast<const IMAGE_DOS_HEADER*>(dllBytes.data());
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return std::unexpected("Invalid DOS signature");

    auto* pNtHeader = std::bit_cast<const IMAGE_NT_HEADERS*>(dllBytes.data() + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return std::unexpected("Invalid NT signature");

    if (pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return std::unexpected("Only x64 DLLs are supported");

    void* pTargetBaseRaw = VirtualAllocEx(hProcess, nullptr, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBaseRaw) return std::unexpected("Failed to allocate memory in target process");

    UniqueRemoteMem pTargetBase(pTargetBaseRaw, RemoteMemDeleter{ hProcess });

    MAPPING_DATA data{
        .pLoadLibraryA = LoadLibraryA,
        .pGetProcAddress = GetProcAddress,
        .pRtlAddFunctionTable = std::bit_cast<f_RtlAddFunctionTable>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddFunctionTable")),
        .pBase = static_cast<std::byte*>(pTargetBase.get()),
        .fdwReasonParam = DLL_PROCESS_ATTACH,
        .reservedParam = nullptr
    };

    if (!WriteProcessMemory(hProcess, pTargetBase.get(), dllBytes.data(), pNtHeader->OptionalHeader.SizeOfHeaders, nullptr)) return std::unexpected("Failed to write headers");

    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProcess, static_cast<std::byte*>(pTargetBase.get()) + pSectionHeader->VirtualAddress, dllBytes.data() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) return std::unexpected("Failed to write section: " + std::string(reinterpret_cast<const char*>(pSectionHeader->Name)));
        }
    }

    void* pDataMemRaw = VirtualAllocEx(hProcess, nullptr, sizeof(MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    UniqueRemoteMem pDataMem(pDataMemRaw, RemoteMemDeleter{ hProcess });
    WriteProcessMemory(hProcess, pDataMem.get(), &data, sizeof(MAPPING_DATA), nullptr);

    const size_t shellcodeSize = reinterpret_cast<uintptr_t>(ShellcodeEnd) - reinterpret_cast<uintptr_t>(Shellcode);
    void* pShellcodeMemRaw = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    UniqueRemoteMem pShellcodeMem(pShellcodeMemRaw, RemoteMemDeleter{ hProcess });
    WriteProcessMemory(hProcess, pShellcodeMem.get(), reinterpret_cast<const void*>(Shellcode), shellcodeSize, nullptr);

    UniqueHandle hThread(CreateRemoteThread(hProcess, nullptr, 0, std::bit_cast<LPTHREAD_START_ROUTINE>(pShellcodeMem.get()), pDataMem.get(), 0, nullptr));
    if (!hThread) return std::unexpected("Failed to create remote thread");

    HINSTANCE hCheck = nullptr;
    DWORD exitCode = 0;
    while (!hCheck) {
        if (!GetExitCodeThread(hThread.get(), &exitCode) || exitCode != STILL_ACTIVE) return std::unexpected("Remote thread terminated unexpectedly with code: " + std::to_string(exitCode));
        MAPPING_DATA dataRead;
        if (!ReadProcessMemory(hProcess, pDataMem.get(), &dataRead, sizeof(MAPPING_DATA), nullptr)) return std::unexpected("Failed to read mapping data");
        hCheck = dataRead.hModule;
        Sleep(10);
    }

    std::vector<std::byte> zeroHeader(pNtHeader->OptionalHeader.SizeOfHeaders, std::byte{ 0 });
    WriteProcessMemory(hProcess, pTargetBase.get(), zeroHeader.data(), zeroHeader.size(), nullptr);

    pTargetBase.release();

    return {};
}


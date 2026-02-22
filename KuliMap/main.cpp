#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mapper.hpp>
#include <TlHelp32.h>
#include <string_view>
#include <vector>

DWORD GetProcessIdByName(std::wstring_view processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create snapshot. Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << std::filesystem::path(argv[0]).filename().string() << " <process name> <dll path>" << std::endl;
        return 1;
    }

    std::string_view processName = argv[1];
    std::filesystem::path dllPath = argv[2];

    if (!std::filesystem::exists(dllPath)) {
        std::cerr << "[-] DLL file does not exist: " << dllPath.string() << std::endl;
        return 1;
    }

    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "[-] Failed to open DLL: " << dllPath.string() << std::endl;
        return 1;
    }

    auto fileSize = file.tellg();
    std::vector<std::byte> buffer(static_cast<size_t>(fileSize));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    std::wstring wProcessName(processName.begin(), processName.end());
    DWORD pid = GetProcessIdByName(wProcessName);
    if (!pid) {
        std::cerr << "[-] Process " << processName << " not found." << std::endl;
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cerr << "[-] OpenProcess failed. Run as Admin! Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[*] Injecting " << dllPath.filename().string() << " into " << processName << " (PID: " << pid << ")..." << std::endl;

    auto result = MapDll(hProc, buffer);
    if (result) {
        std::cout << "[+] Successfully mapped!" << std::endl;
    }
    else {
        std::cerr << "[-] Mapping failed: " << result.error() << std::endl;
    }

    CloseHandle(hProc);
    return 0;
}

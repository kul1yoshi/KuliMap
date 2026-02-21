#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <print>
#include <mapper.hpp>
#include <tlhelp32.h>
#include <string_view>

DWORD GetProcessIdByName(std::wstring_view processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::println("[-] Failed to create snapshot. Error: {}", GetLastError());
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
        std::println("Usage: injector.exe <process name> <dll path>");
        return 1;
    }

    std::string_view processName = argv[1];
    std::filesystem::path dllPath = argv[2];

    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::println("[-] Failed to open DLL: {}", dllPath.string());
        return 1;
    }

    auto fileSize = file.tellg();
    std::vector<std::byte> buffer(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    DWORD pid = GetProcessIdByName(std::wstring(processName.begin(), processName.end()).c_str());
    if (!pid) {
        std::println("[-] Process {} not found.", processName);
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::println("[-] OpenProcess failed. Run as Admin!");
        return 1;
    }

    std::println("[*] Injecting {} into {}...", dllPath.filename().string(), processName);

    auto result = MapDll(hProc, buffer);
    if (result) {
        std::println("[+] Successfully mapped!");
    }
    else {
        std::println("[-] Mapping failed: {}", result.error());
    }

    CloseHandle(hProc);
    return 0;
}

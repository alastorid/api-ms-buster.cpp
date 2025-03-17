#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <set>
#include <algorithm>

const char* knownDllsOrder[] = {
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "advapi32.dll",
    "sechost.dll",
    "rpcrt4.dll",
    "combase.dll",
    "ole32.dll",
    "oleaut32.dll",
    "user32.dll",
    "gdi32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "version.dll",
    "winspool.drv",
    "comdlg32.dll",
    "bcrypt.dll",
    "ncrypt.dll",
    "msvcp_win.dll",
    "ucrtbase.dll",
    "vcruntime140.dll",
    "msvcrt.dll",
    "ws2_32.dll",
    "iphlpapi.dll",
    "powrprof.dll",
    "setupapi.dll",
    "uxtheme.dll",
    "winmm.dll",
    "winhttp.dll",
    "urlmon.dll",
    "mswsock.dll",
    "wldp.dll",
    "profapi.dll",
    "crypt32.dll",
    "wintrust.dll",
    "msasn1.dll",
    "cryptbase.dll",
    "wtsapi32.dll",
    "userenv.dll",
    "netapi32.dll",
    "samcli.dll",
    "wkscli.dll",
    "msi.dll",
    "cfgmgr32.dll",
    "msimg32.dll",
    "dwmapi.dll",
    "dnsapi.dll",
    "cryptsp.dll",
    "dbghelp.dll",
    "imagehlp.dll"
};

struct ImportInfo {
    std::string originalDll;
    std::set<std::string> requiredFunctions;
};

bool CheckDllForFunctions(const char* dllName, const std::set<std::string>& functions) {
    HMODULE hMod = LoadLibraryA(dllName);
    if (!hMod) return false;

    bool hasAllFunctions = true;
    for (const auto& func : functions) {
        if (!GetProcAddress(hMod, func.c_str())) {
            hasAllFunctions = false;
            break;
        }
    }

    FreeLibrary(hMod);
    return hasAllFunctions;
}

std::string ToUpper(const std::string& str) {
    std::string upper = str;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    return upper;
}

std::string FindBestReplacementDll(const ImportInfo& importInfo) {
    std::string upperDll = ToUpper(importInfo.originalDll);
    if (upperDll.find("API-MS-") == std::string::npos &&
        upperDll.find("EXT-MS-") == std::string::npos) {
        return "";
    }

    for (const auto& dll : knownDllsOrder) {
        if (CheckDllForFunctions(dll, importInfo.requiredFunctions)) {
            return dll;
        }
    }
    return "";
}

bool FixPEImports(const char* filepath) {
    try {
        HANDLE hFile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Cannot open file");
        }

        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (!hMapping) {
            CloseHandle(hFile);
            throw std::runtime_error("Cannot create file mapping");
        }

        LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!fileBase) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            throw std::runtime_error("Cannot map view of file");
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            throw std::runtime_error("Invalid DOS signature");
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            throw std::runtime_error("Invalid NT signature");
        }

        DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!importRVA) {
            throw std::runtime_error("No import table found");
        }

        auto RvaToOffset = [ntHeaders](DWORD rva) -> DWORD {
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
                if (rva >= section->VirtualAddress &&
                    rva < section->VirtualAddress + section->Misc.VirtualSize) {
                    return rva - section->VirtualAddress + section->PointerToRawData;
                }
            }
            return 0;
        };

        DWORD importOffset = RvaToOffset(importRVA);
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)fileBase + importOffset);

        std::map<std::string, ImportInfo> importMap;

        while (importDesc->Name) {
            char* dllName = (char*)fileBase + RvaToOffset(importDesc->Name);
            std::string upperDllName = ToUpper(dllName);

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)fileBase +
                RvaToOffset(importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));

            ImportInfo& info = importMap[upperDllName];
            info.originalDll = dllName;

            while (thunk->u1.AddressOfData) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)fileBase +
                        RvaToOffset(thunk->u1.AddressOfData));
                    info.requiredFunctions.insert((char*)importByName->Name);
                }
                thunk++;
            }
            importDesc++;
        }

        importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)fileBase + importOffset);
        int modifiedCount = 0;

        while (importDesc->Name) {
            char* dllName = (char*)fileBase + RvaToOffset(importDesc->Name);
            std::string upperDllName = ToUpper(dllName);

            auto it = importMap.find(upperDllName);
            if (it != importMap.end()) {
                std::string newDll = FindBestReplacementDll(it->second);
                if (!newDll.empty()) {
                    strcpy(dllName, newDll.c_str());
                    modifiedCount++;
                    std::cout << "Redirected: " << upperDllName << " -> " << newDll << std::endl;
                }
                else if (upperDllName.find("API-MS-") != std::string::npos) {
                    std::cout << "Warning: Could not find replacement for " << upperDllName << std::endl;
                    std::cout << "Required functions:" << std::endl;
                    for (const auto& func : it->second.requiredFunctions) {
                        std::cout << "  " << func << std::endl;
                    }
                }
            }
            importDesc++;
        }

        FlushViewOfFile(fileBase, 0);
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        std::cout << "Modified " << modifiedCount << " imports" << std::endl;
        return modifiedCount > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <path_to_exe_or_dll>" << std::endl;
        return 1;
    }

    if (FixPEImports(argv[1])) {
        std::cout << "Successfully fixed imports in " << argv[1] << std::endl;
        return 0;
    }
    else {
        std::cout << "Failed to fix imports in " << argv[1] << std::endl;
        return 1;
    }
}
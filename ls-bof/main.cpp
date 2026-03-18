
#include <beacon.h>
#include <windows.h>
#include <stdio.h>

// Minimal ls implementation as BOF-PE
// Lists directory contents using FindFirstFile/FindNextFile

extern "C" __declspec(dllexport) void go(const char* data, int len) {
    BEACON_INIT;

    // Parse arguments - expect optional path
    datap args = {0};
    BeaconDataParse(&args, (char*)data, len);

    char searchPath[MAX_PATH] = {0};
    const char* path = BeaconDataExtract(&args, nullptr);

    if (path != nullptr && path[0] != '\0') {
        // User provided a path
        sprintf_s(searchPath, sizeof(searchPath), "%s\\*", path);
    } else {
        // Default to current directory
        strcpy_s(searchPath, sizeof(searchPath), ".\\*");
    }

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Error: Cannot open directory (error %d)\n", GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Directory listing for: %s\n\n",
                 (path && path[0]) ? path : ".");
    BeaconPrintf(CALLBACK_OUTPUT, "%-12s  %10s  %s\n", "Type", "Size", "Name");
    BeaconPrintf(CALLBACK_OUTPUT, "%-12s  %10s  %s\n", "----", "----", "----");

    do {
        const char* typeStr;
        char sizeStr[32] = {0};

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            typeStr = "<DIR>";
            strcpy_s(sizeStr, sizeof(sizeStr), "");
        } else {
            typeStr = "<FILE>";
            // Combine high and low parts for 64-bit file size
            ULARGE_INTEGER fileSize;
            fileSize.HighPart = findData.nFileSizeHigh;
            fileSize.LowPart = findData.nFileSizeLow;
            sprintf_s(sizeStr, sizeof(sizeStr), "%llu", fileSize.QuadPart);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%-12s  %10s  %s\n",
                     typeStr, sizeStr, findData.cFileName);

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

// Enable standalone execution with optional path argument
// "z" = null-terminated string (the directory path)
BEACON_MAIN("z", go)

#pragma once

#include <cstdint>

struct PEExportInfo
{
    wchar_t** ExportNames;
    int ExportCount;
};

extern "C"
{
    __declspec(dllexport) int ScanDllExports(const PEExportInfo* peInfo, wchar_t* detection, uint32_t detectionSize);
}

#pragma once

#include <cstdint>

extern "C"
{
    __declspec(dllexport) int CalculateFileSha256(const wchar_t* filePath, wchar_t* hash, uint32_t hashSize);
    __declspec(dllexport) int IsFileTrusted(const wchar_t* filePath, const wchar_t* trustFolderPath);
    __declspec(dllexport) int CreateTrustItemJson(const wchar_t* filePath, const wchar_t* hash, wchar_t* json, uint32_t jsonSize);
}

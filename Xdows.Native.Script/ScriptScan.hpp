#pragma once

#include <cstdint>

struct ScriptScanResult
{
    int Score;
    wchar_t Tags[512];
};

extern "C"
{
    __declspec(dllexport) int ScanScriptFile(const wchar_t* filePath, const uint8_t* content, size_t contentSize, ScriptScanResult* result);
    __declspec(dllexport) int IsScriptFile(const wchar_t* extension);
}

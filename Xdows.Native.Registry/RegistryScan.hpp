#pragma once

#include <cstdint>

extern "C"
{
    __declspec(dllexport) int ScanRegistryKey(const wchar_t* keyPath, wchar_t* threatType, uint32_t threatTypeSize);
}

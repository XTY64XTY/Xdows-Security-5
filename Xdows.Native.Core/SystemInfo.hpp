#pragma once

#include <cstdint>

extern "C"
{
    __declspec(dllexport) bool GetMemoryInfo(uint32_t* loadPercent, wchar_t* display, uint32_t displaySize);
}

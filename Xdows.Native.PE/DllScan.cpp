#include "pch.h"
#include "DllScan.hpp"

#include <string>
#include <vector>
#include <algorithm>

namespace
{
    const std::vector<std::wstring>& GetWhitelistPatterns()
    {
        static const std::vector<std::wstring> patterns = {
            L"Py", L"Scan", L"chromium", L"blink", L"Qt"
        };
        return patterns;
    }

    const std::vector<std::wstring>& GetBlacklistPatterns()
    {
        static const std::vector<std::wstring> patterns = {
            L"Hook", L"Virus", L"Bypass"
        };
        return patterns;
    }

    bool ContainsPattern(const std::wstring& text, const std::wstring& pattern)
    {
        return text.find(pattern) != std::wstring::npos;
    }

    std::wstring ToLower(const std::wstring& str)
    {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }

    bool MatchPatterns(const std::wstring& exportName, const std::vector<std::wstring>& patterns)
    {
        std::wstring exportNameLower = ToLower(exportName);
        
        for (const auto& pattern : patterns)
        {
            std::wstring patternLower = ToLower(pattern);
            if (ContainsPattern(exportNameLower, patternLower))
            {
                return true;
            }
        }
        
        return false;
    }
}

int ScanDllExports(const PEExportInfo* peInfo, wchar_t* detection, uint32_t detectionSize)
{
    if (peInfo == nullptr || detection == nullptr || detectionSize == 0)
    {
        return 0;
    }

    detection[0] = L'\0';

    if (peInfo->ExportNames == nullptr || peInfo->ExportCount <= 0)
    {
        return 0;
    }

    const auto& whitelist = GetWhitelistPatterns();
    const auto& blacklist = GetBlacklistPatterns();

    for (int i = 0; i < peInfo->ExportCount; ++i)
    {
        if (peInfo->ExportNames[i] == nullptr)
        {
            continue;
        }

        std::wstring exportName(peInfo->ExportNames[i]);

        if (MatchPatterns(exportName, whitelist))
        {
            continue;
        }

        if (MatchPatterns(exportName, blacklist))
        {
            const wchar_t* threatName = L"SuspiciousDllExport";
            size_t threatNameLen = wcslen(threatName);
            
            if (detectionSize > threatNameLen)
            {
                wcscpy_s(detection, detectionSize, threatName);
            }
            
            return 1;
        }
    }

    return 0;
}

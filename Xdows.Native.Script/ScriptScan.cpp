#include "pch.h"
#include "ScriptScan.hpp"

#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <sstream>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

namespace
{
    const uint32_t MAX_CONTENT_SIZE = 10485760;
    const uint32_t MAX_SCORE = 1000;

    const std::set<std::wstring>& GetScriptExtensions()
    {
        static const std::set<std::wstring> extensions = {
            L".ps1", L".psm1", L".psd1",
            L".vbs", L".vbe",
            L".js", L".jse",
            L".bat", L".cmd",
            L".py", L".pyw",
            L".sh", L".bash", L".zsh",
            L".pl", L".pm",
            L".rb",
            L".php", L".phtml", L".php3", L".php4", L".php5",
            L".lnk"
        };
        return extensions;
    }

    struct DetectionPattern
    {
        std::wstring Pattern;
        int Score;
        std::wstring Tag;
        pcre2_code* CompiledPattern;
    };

    std::vector<DetectionPattern> g_genericPatterns;
    std::vector<DetectionPattern> g_powershellPatterns;
    std::vector<DetectionPattern> g_batchPatterns;
    bool g_patternsInitialized = false;

    std::wstring ToLower(const std::wstring& str)
    {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }

    std::string ToUtf8(const std::wstring& wstr)
    {
        if (wstr.empty()) return std::string();
        
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, result.data(), size, nullptr, nullptr);
        return result;
    }

    pcre2_code* CompilePattern(const std::wstring& pattern)
    {
        std::string utf8Pattern = ToUtf8(pattern);
        
        int errorNumber = 0;
        PCRE2_SIZE errorOffset = 0;
        
        pcre2_code* re = pcre2_compile(
            reinterpret_cast<PCRE2_SPTR>(utf8Pattern.c_str()),
            PCRE2_ZERO_TERMINATED,
            PCRE2_CASELESS,
            &errorNumber,
            &errorOffset,
            nullptr);
        
        return re;
    }

    void InitializePatterns()
    {
        if (g_patternsInitialized) return;

        struct PatternDef { std::wstring pattern; int score; std::wstring tag; };
        
        std::vector<PatternDef> genericDefs = {
            {L"eval\\(|Invoke-Expression|Execute\\(|exec\\(", 20, L"DynamicExecution"},
            {L"base64|FromBase64String|atob|btoa", 15, L"EncodedContent"},
            {L"(download|wget|curl|invoke-webrequest|fetch\\s*\\()", 20, L"DownloadBehavior"},
            {L"(http|https|ftp)://", 10, L"NetworkActivity"},
            {L"(delete|remove|copy|move|create\\s+file|write\\s+file)", 10, L"FileOperation"},
            {L"(reg\\s+|registry|regedit|reg.exe)", 15, L"RegistryOperation"},
            {L"(start-process|createobject|wscript.shell|shell.application)", 15, L"ProcessOperation"},
            {L"(startup|runonce|autorun|msconfig)", 20, L"PersistenceMechanism"},
            {L"(nyancat|rainbow|memz|trollface)", 30, L"MEMZSignature"},
            {L"(delete\\s+.*system|format\\s+|shutdown|reboot|blue\\s+screen)", 25, L"SystemDestruction"}
        };

        for (const auto& def : genericDefs)
        {
            pcre2_code* compiled = CompilePattern(def.pattern);
            if (compiled)
            {
                g_genericPatterns.push_back({def.pattern, def.score, def.tag, compiled});
            }
        }

        std::vector<PatternDef> powershellDefs = {
            {L"-executionpolicy\\s+bypass", 20, L"BypassExecutionPolicy"},
            {L"-windowstyle\\s+hidden", 15, L"HiddenWindow"},
            {L"(reflection|assembly.load|loadfrom)", 15, L"ReflectionUsage"},
            {L"(add-type|dllimport|getmodulehandle)", 15, L"WinAPIUsage"},
            {L"new-object\\s+-comobject", 10, L"COMObjectUsage"}
        };

        for (const auto& def : powershellDefs)
        {
            pcre2_code* compiled = CompilePattern(def.pattern);
            if (compiled)
            {
                g_powershellPatterns.push_back({def.pattern, def.score, def.tag, compiled});
            }
        }

        std::vector<PatternDef> batchDefs = {
            {L"@echo\\s+off", 5, L"HiddenCommands"},
            {L"powershell\\s+", 10, L"PowerShellInBatch"},
            {L"certutil\\s+", 15, L"CertutilUsage"},
            {L"bitsadmin\\s+", 15, L"BitsadminUsage"},
            {L"(del\\s+[/sfq]|format\\s+|rmdir\\s+[/sq]|shutdown\\s+[/sfr])", 25, L"SystemDestruction"},
            {L"(reg\\s+(add|delete)|regedit)", 20, L"RegistryModification"}
        };

        for (const auto& def : batchDefs)
        {
            pcre2_code* compiled = CompilePattern(def.pattern);
            if (compiled)
            {
                g_batchPatterns.push_back({def.pattern, def.score, def.tag, compiled});
            }
        }

        g_patternsInitialized = true;
    }

    bool MatchPattern(const std::string& content, const DetectionPattern& pattern)
    {
        if (pattern.CompiledPattern == nullptr) return false;

        pcre2_match_data* matchData = pcre2_match_data_create_from_pattern(pattern.CompiledPattern, nullptr);
        if (matchData == nullptr) return false;

        int rc = pcre2_match(
            pattern.CompiledPattern,
            reinterpret_cast<PCRE2_SPTR>(content.c_str()),
            content.length(),
            0,
            0,
            matchData,
            nullptr);

        pcre2_match_data_free(matchData);
        return rc >= 0;
    }

    void ScanWithPatterns(const std::string& content, const std::vector<DetectionPattern>& patterns, int& totalScore, std::set<std::wstring>& tags)
    {
        for (const auto& pattern : patterns)
        {
            if (MatchPattern(content, pattern))
            {
                totalScore += pattern.Score;
                tags.insert(pattern.Tag);
            }
        }
    }

    std::wstring GetFileExtension(const std::wstring& filePath)
    {
        size_t pos = filePath.rfind(L'.');
        if (pos != std::wstring::npos)
        {
            return ToLower(filePath.substr(pos));
        }
        return L"";
    }

    bool IsPowerShellFile(const std::wstring& ext)
    {
        return ext == L".ps1" || ext == L".psm1" || ext == L".psd1";
    }

    bool IsBatchFile(const std::wstring& ext)
    {
        return ext == L".bat" || ext == L".cmd";
    }

    std::string ConvertToUtf8(const uint8_t* content, size_t size)
    {
        if (size >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF)
        {
            return std::string(reinterpret_cast<const char*>(content + 3), size - 3);
        }

        if (size >= 2 && content[0] == 0xFF && content[1] == 0xFE)
        {
            size_t charCount = (size - 2) / 2;
            std::wstring wstr(reinterpret_cast<const wchar_t*>(content + 2), charCount);
            return ToUtf8(wstr);
        }

        if (size >= 2 && content[0] == 0xFE && content[1] == 0xFF)
        {
            std::string result;
            for (size_t i = 2; i + 1 < size; i += 2)
            {
                wchar_t wc = (static_cast<wchar_t>(content[i]) << 8) | content[i + 1];
                char utf8Buf[4] = {0};
                int len = WideCharToMultiByte(CP_UTF8, 0, &wc, 1, utf8Buf, 4, nullptr, nullptr);
                result.append(utf8Buf, len);
            }
            return result;
        }

        return std::string(reinterpret_cast<const char*>(content), size);
    }
}

int ScanScriptFile(const wchar_t* filePath, const uint8_t* content, size_t contentSize, ScriptScanResult* result)
{
    if (result == nullptr)
    {
        return 0;
    }

    result->Score = 0;
    result->Tags[0] = L'\0';

    InitializePatterns();

    if (content == nullptr || contentSize == 0)
    {
        return 1;
    }

    size_t scanSize = (std::min)(contentSize, static_cast<size_t>(MAX_CONTENT_SIZE));
    std::string utf8Content = ConvertToUtf8(content, scanSize);

    std::wstring ext;
    if (filePath != nullptr)
    {
        ext = GetFileExtension(filePath);
    }

    int totalScore = 0;
    std::set<std::wstring> tags;

    ScanWithPatterns(utf8Content, g_genericPatterns, totalScore, tags);

    if (IsPowerShellFile(ext))
    {
        ScanWithPatterns(utf8Content, g_powershellPatterns, totalScore, tags);
    }
    else if (IsBatchFile(ext))
    {
        ScanWithPatterns(utf8Content, g_batchPatterns, totalScore, tags);
    }

    result->Score = (std::min)(totalScore, static_cast<int>(MAX_SCORE));

    std::wostringstream tagStream;
    bool firstTag = true;
    for (const auto& tag : tags)
    {
        if (!firstTag)
        {
            tagStream << L" ";
        }
        firstTag = false;
        tagStream << tag;
    }

    std::wstring tagStr = tagStream.str();
    if (tagStr.size() < 512)
    {
        wcscpy_s(result->Tags, 512, tagStr.c_str());
    }

    return 1;
}

int IsScriptFile(const wchar_t* extension)
{
    if (extension == nullptr)
    {
        return 0;
    }

    std::wstring ext = ToLower(extension);
    const auto& extensions = GetScriptExtensions();

    return extensions.find(ext) != extensions.end() ? 1 : 0;
}

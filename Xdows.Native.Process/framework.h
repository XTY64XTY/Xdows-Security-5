#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <thread>
#include <chrono>
#include <cstdint>

#pragma comment(lib, "psapi.lib")

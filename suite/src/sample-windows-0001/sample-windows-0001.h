#pragma once

#include "platform/windows_def.h"

#include <string>
#include <set>

#include "enumerator/process_enumerator.h"
#include "enumerator/module_enumerator.h"
#include "injector/injector.h"

std::set<std::wstring> ParseCommandLineToSetW(LPWSTR cmdLine);
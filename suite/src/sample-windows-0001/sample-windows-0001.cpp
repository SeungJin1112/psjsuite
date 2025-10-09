#include "sample-windows-0001.h"

std::set<std::wstring> ParseCommandLineToSetW(LPWSTR cmdLine)
{
    std::set<std::wstring> ret;

    int argc = 0x00;
    LPWSTR* argv = CommandLineToArgvW(cmdLine, &argc);

    for (int i = 0x00; i < argc; i++)
        ret.insert(argv[i]);

    LocalFree(argv);
    return ret;
}

int WINAPI wWinMain(
    HINSTANCE instance,
    HINSTANCE prevInstance,
    LPWSTR cmdLine,
    int cmdShow)
{
    std::set<std::wstring> args = ParseCommandLineToSetW(cmdLine);

    return 0x00;
}
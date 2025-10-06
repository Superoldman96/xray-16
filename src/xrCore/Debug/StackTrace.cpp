#include "stdafx.h"

#include "StackTrace.h"

#ifdef XR_PLATFORM_WINDOWS
#   if defined(XR_ARCHITECTURE_X86)
#       define MACHINE_TYPE IMAGE_FILE_MACHINE_I386
#   elif defined(XR_ARCHITECTURE_X64)
#       define MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
#   elif defined(XR_ARCHITECTURE_ARM)
#       define MACHINE_TYPE IMAGE_FILE_MACHINE_ARM
#   elif defined(XR_ARCHITECTURE_ARM64)
#       define MACHINE_TYPE IMAGE_FILE_MACHINE_ARM64
#   elif defined(XR_ARCHITECTURE_IA64)
#       define MACHINE_TYPE IMAGE_FILE_MACHINE_IA64
#   else
#       error CPU architecture is not supported.
#   endif
#elif defined(XR_PLATFORM_LINUX) || defined(XR_PLATFORM_APPLE) || defined(XR_PLATFORM_BSD)
#   ifdef BACKTRACE_AVAILABLE
#       include <execinfo.h>

#       ifdef CXXABI_AVAILABLE
#           include <cxxabi.h>
#           include <dlfcn.h>
#       endif
#   endif
#endif

#ifdef XR_PLATFORM_WINDOWS
namespace
{
HMODULE s_dbghelp{};

decltype(&SymInitialize)          symInitialize{};
decltype(&SymCleanup)             symCleanup{};
decltype(&SymGetOptions)          symGetOptions{};
decltype(&SymSetOptions)          symSetOptions{};
decltype(&StackWalk)              stackWalk{};
decltype(&SymFunctionTableAccess) symFunctionTableAccess{};
decltype(&SymGetModuleBase)       symGetModuleBase{};
decltype(&SymGetSymFromAddr)      symGetSymFromAddr{};
decltype(&SymGetLineFromAddr)     symGetLineFromAddr{};

template <typename T>
ICF void load_function(T& func, cpcstr name)
{
    func = reinterpret_cast<T>(GetProcAddress(s_dbghelp, name)); // NOLINT(clang-diagnostic-cast-function-type-strict)

    if (!func)
        Msg("! [StackTraceBuilder] Failed to load %s function", name);
}

#   define STRINGIZE_HELPER(value) #value
#   define STRINGIZE(value) STRINGIZE_HELPER(value)

ICF void init_dbghelp()
{
    s_dbghelp = GetModuleHandleA("dbghelp.dll");
    if (!s_dbghelp)
    {
        Log("! [StackTraceBuilder] Failed to load dbghelp.dll");
        return;
    }

    load_function(symGetOptions, "SymGetOptions");
    load_function(symSetOptions, "SymSetOptions");
    load_function(symInitialize, "SymInitialize");
    load_function(symCleanup,    "SymCleanup");

    load_function(stackWalk, STRINGIZE(StackWalk));
    load_function(symGetModuleBase, STRINGIZE(SymGetModuleBase));
    load_function(symGetSymFromAddr, STRINGIZE(SymGetSymFromAddr));
    load_function(symGetLineFromAddr, STRINGIZE(SymGetLineFromAddr));
    load_function(symFunctionTableAccess, STRINGIZE(SymFunctionTableAccess));
}

#   undef STRINGIZE_HELPER
#   undef STRINGIZE
} // namespace

StackTraceBuilder::StackTraceBuilder()
{
    if (isInitialized)
        return;

    if (!s_dbghelp)
        init_dbghelp();

    u32 dwOptions = symGetOptions();
    symSetOptions(dwOptions | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

    isInitialized = symInitialize(GetCurrentProcess(), nullptr, TRUE);

    if (!isInitialized)
    {
        Msg("[StackTraceBuilder::Build] SymInitialize failed with error: 0x%u", GetLastError());
    }
}

StackTraceBuilder::~StackTraceBuilder()
{
    if (!isInitialized)
        return;

    symCleanup(GetCurrentProcess());
}

bool StackTraceBuilder::GetNextStackFrameString(LPSTACKFRAME stackFrame, PCONTEXT threadCtx, xr_string& frameStr)
{
    BOOL result = stackWalk(MACHINE_TYPE, GetCurrentProcess(), GetCurrentThread(), stackFrame, threadCtx, nullptr,
        symFunctionTableAccess, symGetModuleBase, nullptr);

    if (result == FALSE || stackFrame->AddrPC.Offset == 0)
    {
        return false;
    }

    frameStr.clear();
    string512 formatBuff;

    ///
    /// Module name
    ///
    HINSTANCE hModule = (HINSTANCE)symGetModuleBase(GetCurrentProcess(), stackFrame->AddrPC.Offset);
    if (hModule && GetModuleFileName(hModule, formatBuff, _countof(formatBuff)))
    {
        frameStr.append(formatBuff);
    }

    ///
    /// Address
    ///
    xr_sprintf(formatBuff, _countof(formatBuff), " at %p", stackFrame->AddrPC.Offset);
    frameStr.append(formatBuff);

    ///
    /// Function info
    ///
    u8 arrSymBuffer[512]{};
    PIMAGEHLP_SYMBOL functionInfo = reinterpret_cast<PIMAGEHLP_SYMBOL>(arrSymBuffer);
    functionInfo->SizeOfStruct  = sizeof(*functionInfo);
    functionInfo->MaxNameLength = sizeof(arrSymBuffer) - sizeof(*functionInfo) + 1;
    DWORD_PTR dwFunctionOffset;

    result = symGetSymFromAddr(GetCurrentProcess(), stackFrame->AddrPC.Offset, &dwFunctionOffset, functionInfo);

    if (result)
    {
        if (dwFunctionOffset)
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " %s() + %Iu byte(s)", functionInfo->Name, dwFunctionOffset);
        }
        else
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " %s()", functionInfo->Name);
        }
        frameStr.append(formatBuff);
    }

    ///
    /// Source info
    ///
    DWORD dwLineOffset;
    IMAGEHLP_LINE sourceInfo = {};
    sourceInfo.SizeOfStruct = sizeof(sourceInfo);

    result = symGetLineFromAddr(GetCurrentProcess(), stackFrame->AddrPC.Offset, &dwLineOffset, &sourceInfo);

    if (result)
    {
        if (dwLineOffset)
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " in %s line %u + %u byte(s)", sourceInfo.FileName,
                sourceInfo.LineNumber, dwLineOffset);
        }
        else
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " in %s line %u", sourceInfo.FileName, sourceInfo.LineNumber);
        }
        frameStr.append(formatBuff);
    }

    return true;
}

xr_vector<xr_string> StackTraceBuilder::Build(PCONTEXT threadCtx, u16 maxFramesCount)
{
    if (!isInitialized)
        return {};

    ScopeLock Lock(&dbgHelpLock);

    xr_vector<xr_string> traceResult;
    xr_string frameStr;

    traceResult.reserve(maxFramesCount);

    STACKFRAME stackFrame{};
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrBStore.Mode = AddrModeFlat;

    // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-stackframe
    // https://github.com/reactos/reactos/blob/master/base/applications/drwtsn32/stacktrace.cpp
#if defined XR_ARCHITECTURE_X86
    stackFrame.AddrPC.Offset = threadCtx->Eip;
    stackFrame.AddrStack.Offset = threadCtx->Esp;
    stackFrame.AddrFrame.Offset = threadCtx->Ebp;
#elif defined XR_ARCHITECTURE_X64
    stackFrame.AddrPC.Offset = threadCtx->Rip;
    stackFrame.AddrStack.Offset = threadCtx->Rsp;
    stackFrame.AddrFrame.Offset = threadCtx->Rbp;
#elif defined XR_ARCHITECTURE_ARM
    stackFrame.AddrPC.Offset = threadCtx->Pc;
    stackFrame.AddrStack.Offset = threadCtx->Sp;
    stackFrame.AddrFrame.Offset = threadCtx->R11;
#elif defined XR_ARCHITECTURE_ARM64
    stackFrame.AddrPC.Offset = threadCtx->Pc;
    stackFrame.AddrStack.Offset = threadCtx->Sp;
    stackFrame.AddrFrame.Offset = threadCtx->Fp;
#elif defined XR_ARCHITECTURE_IA64
    stackFrame.AddrPC.Offset = threadCtx->StIIP;
    stackFrame.AddrStack.Offset = threadCtx->IntSp;
    stackFrame.AddrBStore.Offset = threadCtx->RsBSP;
#else
#   error CPU architecture is not supported.
#endif

    while (GetNextStackFrameString(&stackFrame, threadCtx, frameStr) && traceResult.size() <= maxFramesCount)
    {
        traceResult.push_back(frameStr);
    }

    return traceResult;
}

xr_vector<xr_string> StackTraceBuilder::Build(u16 maxFramesCount)
{
    CONTEXT currentThreadCtx = {};

    RtlCaptureContext(&currentThreadCtx); /// GetThreadContext can't be used on the current thread
    currentThreadCtx.ContextFlags = CONTEXT_FULL;

    return Build(&currentThreadCtx, maxFramesCount);
}
#elif defined(BACKTRACE_AVAILABLE)
xr_vector<xr_string> xrDebug::Build(u16 maxFramesCount)
{
    xr_vector<xr_string> result;

    void** array = reinterpret_cast<void**>(xr_alloca(sizeof(void*) * maxFramesCount));
    int nptrs = backtrace(array, maxFramesCount); // get void*'s for all entries on the stack
    char** strings = backtrace_symbols(array, nptrs);

    if (strings)
    {
        size_t demangledBufSize = 0;
        char* demangledName = nullptr;
        for (int i = 1; i < nptrs; i++) // skip this function
        {
            char* functionName = strings[i];

#   ifdef CXXABI_AVAILABLE
            Dl_info info;

            if (dladdr(array[i], &info))
            {
                if (info.dli_sname)
                {
                    int status = -1;
                    demangledName = abi::__cxa_demangle(info.dli_sname, demangledName, &demangledBufSize, &status);
                    if (status == 0)
                    {
                        functionName = demangledName;
                    }
                }
            }
#   endif
            result.emplace_back(functionName);
        }
        ::free(demangledName);
    }

    return result;
}
#else
xr_vector<xr_string> StackTraceBuilder::Build(u16 maxFramesCount)
{
#   pragma todo("Implement stack trace for this platform")
    return { "Stack trace is not implemented for this platform." };
}
#endif

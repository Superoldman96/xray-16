#pragma once

#ifdef XR_PLATFORM_WINDOWS
#include <DbgHelp.h>
#elif defined(XR_PLATFORM_LINUX) || defined(XR_PLATFORM_APPLE) || defined(XR_PLATFORM_BSD)
#   if __has_include(<execinfo.h>)
#       define BACKTRACE_AVAILABLE
#       if __has_include(<cxxabi.h>)
#           define CXXABI_AVAILABLE
#       endif
#   endif
#endif

class StackTraceBuilder
{
public:
    StackTraceBuilder();
    ~StackTraceBuilder();

    xr_vector<xr_string> Build(u16 maxFramesCount = 512);

#ifdef XR_PLATFORM_WINDOWS
    xr_vector<xr_string> Build(PCONTEXT threadCtx, u16 maxFramesCount);

private:
    bool GetNextStackFrameString(LPSTACKFRAME stackFrame, PCONTEXT threadCtx, xr_string& frameStr);

private:
    Lock dbgHelpLock;
    bool isInitialized{};
#endif
};

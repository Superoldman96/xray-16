#include "Pch.hpp"
#include "Core.hpp"
#include "xrCore/xrCore.h"
#include <msclr/marshal_cppstd.h>

namespace XRay
{
namespace ManagedApi
{
namespace Core
{

static void LogCallbackWrapper(const char* msg)
{
    if (!Core::ManagedLogCallback)
        return;
    String^ tmpMsg = msg ? gcnew String(msg) : nullptr;
    Core::ManagedLogCallback(tmpMsg);
}

void Core::Initialize(String^ appName, LogCallback^ logCallback, bool initFs, String^ fsFileName)
{
    ManagedLogCallback = logCallback;
    std::string appNameC = msclr::interop::marshal_as<std::string>(appName);
    if (fsFileName)
    {
        std::string fsFileNameC = msclr::interop::marshal_as<std::string>(fsFileName);
        ::Core._initialize(appNameC.c_str(), LogCallbackWrapper, initFs, fsFileNameC.c_str());
    }
    else
        ::Core._initialize(appNameC.c_str(), LogCallbackWrapper, initFs, nullptr);
}

void Core::Initialize(String^ appName, LogCallback^ logCallback, bool initFs)
{
    Core::Initialize(appName, logCallback, initFs, nullptr);
}

void Core::Initialize(String^ appName, LogCallback^ logCallback)
{
    Core::Initialize(appName, logCallback, false, nullptr);
}

void Core::Initialize(String^ appName)
{
    Core::Initialize(appName, nullptr, false, nullptr);
}

void Core::Destroy()
{
    ::Core._destroy();
}

}
}
}

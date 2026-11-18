#include "ValidateScripts.hpp"
#include "Addresses.hpp"
#include "App.hpp"
#include "Detail/AddressHashes.hpp"
#include "Hook.hpp"
#include "RED4ext/Scripting/ScriptReport.hpp"
#include "ScriptValidationError.hpp"
#include "Systems/PluginSystem.hpp"
#include "Systems/ScriptCompilationSystem.hpp"
#include "Utils.hpp"

#include <fmt/xchar.h>
#include <spdlog/spdlog.h>

#ifndef RED4EXT_PLATFORM_MACOS
#include <Windows.h>
#endif

#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace
{
bool isAttached = false;

using CreateScriptReportAndLoad_t = uint64_t (*)(void* a0, void* a1, uint32_t aFillErrors, void* aErrors, uint32_t aMaxErrors);
uint64_t _CreateScriptReportAndLoad(void* a0, void* a1, uint32_t aFillErrors, void* aErrors, uint32_t aMaxErrors);
Hook<CreateScriptReportAndLoad_t> CreateScriptReportAndLoad(
    RED4ext::RelocFunc<CreateScriptReportAndLoad_t>(0x3c45e80),
    &_CreateScriptReportAndLoad);

uint64_t _CreateScriptReportAndLoad(void* a0, void* a1, uint32_t aFillErrors, void* aErrors, uint32_t aMaxErrors)
{
    Log::info("CreateScriptReportAndLoad: forcing aFillErrors = 1");
    auto res = CreateScriptReportAndLoad(a0, a1, 1, aErrors, aMaxErrors);
    auto* errors = reinterpret_cast<RED4ext::DynArray<RED4ext::CString>*>(aErrors);
    if (errors)
    {
        Log::info("CreateScriptReportAndLoad: finished with res = {:#x}, error count = {}", res, errors->Size());
        for (std::uint32_t i = 0; i < errors->Size(); ++i)
        {
            Log::error("ScriptReport [{}]: {}", i, (*errors)[i].c_str());
        }
    }
    else
    {
        Log::info("CreateScriptReportAndLoad: finished with res = {:#x}, errors ptr is null", res);
    }
    return res;
}

bool _ScriptValidator_Validate(uint64_t self, uint64_t a1, RED4ext::ScriptReport& aReport);
Hook<decltype(&_ScriptValidator_Validate)> ScriptValidator_Validate(Hashes::ScriptValidator_Validate,
                                                                    &_ScriptValidator_Validate);

bool _ScriptValidator_Validate(uint64_t self, uint64_t a1, RED4ext::ScriptReport& aReport)
{
    aReport.fillErrors = true;
    const auto result = ScriptValidator_Validate(self, a1, aReport);
    std::vector<ValidationError> validationErrors;

    for (std::uint32_t i = 0; i < std::max(aReport.errors->Size(), 1u) - 1; ++i)
    {
        auto message = (*aReport.errors)[i].c_str();

        // Check if this error is an allowed Codeware resource wrapper type match:
        // Codeware's ResourceRef maps to native rRef:<Type>
        // Codeware's ResourceAsyncRef maps to native raRef:<Type>
        // Codeware's CurveData maps to native CurveData:<Type>
        if ((strstr(message, "type 'ResourceRef' does not match with the native one 'rRef:") != nullptr) ||
            (strstr(message, "type 'ResourceAsyncRef' does not match with the native one 'raRef:") != nullptr) ||
            (strstr(message, "type 'ResourceRef' does not match with the native one 'raRef:") != nullptr) ||
            (strstr(message, "type 'CurveData") != nullptr && strstr(message, "does not match with the native one 'CurveData:") != nullptr))
        {
            Log::warn("Script validation warning (compatible wrapper type): {}", message);
            continue;
        }

        const auto error = ValidationError::FromString(message);
        validationErrors.push_back(error);

        auto ref = error.GetSourceRef();
        if (ref)
        {
            Log::error("Script validation error: {} at {}:{}", message, ref->file, ref->line + 1);
        }
        else
        {
            Log::error("Script validation error: {}", message);
        }
    }

    const auto& incompatiblePlugins = App::Get()->GetPluginSystem()->GetIncompatiblePlugins();
    const auto message = WritePopupMessage(validationErrors, incompatiblePlugins);
    if (message)
    {
        SHOW_MESSAGE_BOX_AND_EXIT_FILE_LINE(L"{}", message.value());
    }

    if (validationErrors.empty() && incompatiblePlugins.empty())
    {
        Log::info("Script validation passed (compatible wrapper types permitted)");
        if (aReport.errors)
        {
            aReport.errors->Clear();
        }
        return true;
    }

    return result;
}
} // namespace

bool Hooks::ValidateScripts::Attach()
{
    Log::trace("Trying to attach the hook for validate scripts at {:#x}...", ScriptValidator_Validate.GetAddress());

    auto result = ScriptValidator_Validate.Attach();
    if (result != NO_ERROR)
    {
        Log::error("Could not attach the hook for validate scripts. Detour error code: {}", result);
    }
    else
    {
        Log::trace("The hook for validate scripts was attached");
    }

    isAttached = result == NO_ERROR;
    CreateScriptReportAndLoad.Attach();
    return isAttached;
}

bool Hooks::ValidateScripts::Detach()
{
    CreateScriptReportAndLoad.Detach();
    if (!isAttached)
    {
        return false;
    }

    Log::trace("Trying to detach the hook for validate scripts at {:#x}...", ScriptValidator_Validate.GetAddress());

    auto result = ScriptValidator_Validate.Detach();
    if (result != NO_ERROR)
    {
        Log::error("Could not detach the hook for validate scripts. Detour error code: {}", result);
    }
    else
    {
        Log::trace("The hook for validate scripts was detached");
    }

    isAttached = result != NO_ERROR;
    return !isAttached;
}

std::optional<std::wstring> WritePopupMessage(const std::vector<ValidationError>& validationErrors,
                                              const std::vector<PluginSystem::PluginName>& incompatiblePlugins)
{
    if (validationErrors.empty())
    {
        return {};
    }

    std::unordered_set<std::string_view> faultyScriptFiles;

    for (const auto& error : validationErrors)
    {
        if (const auto ref = error.GetSourceRef())
        {
            faultyScriptFiles.insert(ref->file);
        }
    }

    if (faultyScriptFiles.empty() && incompatiblePlugins.empty())
    {
        return L"Script validation has failed for an unknown reason. "
               L"You should verify game files with Steam/GOG and retry.";
    }

    fmt::wmemory_buffer message;
    auto outIt = std::back_inserter(message);

    if (!incompatiblePlugins.empty())
    {
        fmt::format_to(outIt, L"The following RED4ext plugins could not be loaded because they are "
                              L"incompatible with the current version of the game:\n");

        for (const auto& plugin : incompatiblePlugins)
        {
            fmt::format_to(outIt, L"- {}\n", plugin);
        }
        fmt::format_to(outIt, L"\n");
    }

    if (!faultyScriptFiles.empty())
    {
        fmt::format_to(outIt, L"The following scripts contain invalid native definitions and will prevent "
                              L"your game from starting:\n");

        for (const auto& file : faultyScriptFiles)
        {
            fmt::format_to(outIt, L"- {}\n", Utils::Widen(file));
        }
        fmt::format_to(outIt, L"\n");
    }

    fmt::format_to(outIt, L"Check if these mods are up-to-date and installed correctly. If you keep seeing "
                          L"this message after updating/re-installing them, you might have to remove them "
                          L"in order to play the game.\n"
                          L"More details can be found in the logs.\n");

    return std::wstring(message.data(), message.size());
}

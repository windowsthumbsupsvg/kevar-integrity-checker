#define _WIN32_DCOM
#include <windows.h>
#include <winternl.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include <string>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ntdll.lib")

namespace Color {
    constexpr const char* Reset = "\033[0m";
    constexpr const char* Cyan  = "\033[96m";
    constexpr const char* Bold  = "\033[1m";
    constexpr const char* Green = "\033[92m";
    constexpr const char* Red   = "\033[91m";
}

void EnableAnsiConsole() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, mode);
    }
}

void PrintStatusLine(const char* label, bool isOn) {
    std::cout << "  " << label << " : ";
    if (isOn) {
        std::cout << Color::Green << "(Turned on)" << Color::Reset << "\n";
    } else {
        std::cout << Color::Red << "(Turned off)" << Color::Reset << "\n";
    }
}

bool CheckUefiSecureBoot() {
    // Adjust token privilege for firmware variables (best-effort)
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp{};
        LUID luid{};
        if (LookupPrivilegeValueW(nullptr, L"SeSystemEnvironmentPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(hToken);
    }

    BYTE sbVal = 0;
    SetLastError(ERROR_SUCCESS);
    DWORD bytesRead = GetFirmwareEnvironmentVariableW(
        L"SecureBoot",
        L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        &sbVal,
        sizeof(sbVal)
    );

    if (bytesRead >= sizeof(BYTE)) {
        return sbVal == 1;
    }

    // Fallback to Windows registry state key
    DWORD regVal = 0;
    DWORD regSize = sizeof(regVal);
    LONG res = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"UEFISecureBootEnabled",
        RRF_RT_DWORD,
        nullptr,
        &regVal,
        &regSize
    );
    return (res == ERROR_SUCCESS && regVal == 1);
}

bool CheckDmaProtection() {
    using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return false;

    auto NtQuerySysInfo = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(hNtDll, "NtQuerySystemInformation")
    );
    if (!NtQuerySysInfo) return false;

    // SystemDmaGuardPolicyInformation = 202
    constexpr ULONG SystemDmaGuardPolicyInformation = 202;
    BYTE policyByte = 0;
    ULONG retLen = 0;

    NTSTATUS status = NtQuerySysInfo(
        SystemDmaGuardPolicyInformation,
        &policyByte,
        sizeof(policyByte),
        &retLen
    );

    // 0 = NT_SUCCESS; non-zero policyByte indicates DMA guard policy active
    return (status == 0 && policyByte != 0);
}

class WmiSession {
public:
    bool Init(const wchar_t* ns) {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return false;
        initializedCom_ = (hr != RPC_E_CHANGED_MODE);

        if (!securitySet_) {
            hr = CoInitializeSecurity(
                nullptr, -1, nullptr, nullptr,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE, nullptr
            );
            if (SUCCEEDED(hr) || hr == RPC_E_TOO_LATE) {
                securitySet_ = true;
            }
        }

        IWbemLocator* pLoc = nullptr;
        hr = CoCreateInstance(
            CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&pLoc)
        );
        if (FAILED(hr)) return false;

        hr = pLoc->ConnectServer(_bstr_t(ns), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc_);
        pLoc->Release();
        if (FAILED(hr)) return false;

        CoSetProxyBlanket(
            pSvc_, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE
        );
        return true;
    }

    IWbemServices* Service() const { return pSvc_; }

    ~WmiSession() {
        if (pSvc_) pSvc_->Release();
        if (initializedCom_) CoUninitialize();
    }

private:
    IWbemServices* pSvc_ = nullptr;
    bool initializedCom_ = false;
    inline static bool securitySet_ = false;
};

bool CheckHvci() {
    WmiSession wmi;
    if (!wmi.Init(L"root\\Microsoft\\Windows\\DeviceGuard")) return false;

    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = wmi.Service()->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT SecurityServicesRunning FROM Win32_DeviceGuard"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnum
    );
    if (FAILED(hr) || !pEnum) return false;

    bool hvciRunning = false;
    IWbemClassObject* pObj = nullptr;
    ULONG uReturn = 0;

    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK && uReturn == 1) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        if (SUCCEEDED(pObj->Get(L"SecurityServicesRunning", 0, &vtProp, nullptr, nullptr))) {
            if ((vtProp.vt & VT_ARRAY) && vtProp.parray) {
                LONG lBound = 0, uBound = 0;
                SafeArrayGetLBound(vtProp.parray, 1, &lBound);
                SafeArrayGetUBound(vtProp.parray, 1, &uBound);
                for (LONG i = lBound; i <= uBound; ++i) {
                    VARIANT item;
                    VariantInit(&item);
                    if (SafeArrayGetElement(vtProp.parray, &i, &item) == S_OK) {
                        LONG val = 0;
                        if (item.vt == VT_I4 || item.vt == VT_UI4) val = item.lVal;
                        else if (item.vt == VT_I2 || item.vt == VT_UI2) val = item.iVal;
                        // 2 = Hypervisor-protected Code Integrity (HVCI)
                        if (val == 2) {
                            hvciRunning = true;
                        }
                        VariantClear(&item);
                    }
                }
            }
        }
        VariantClear(&vtProp);
        pObj->Release();
    }

    pEnum->Release();
    return hvciRunning;
}

bool CheckTpm20() {
    WmiSession wmi;
    if (!wmi.Init(L"root\\CIMV2\\Security\\MicrosoftTpm")) return false;

    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = wmi.Service()->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT IsEnabled_InitialValue, IsActivated_InitialValue, SpecVersion FROM Win32_Tpm"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnum
    );
    if (FAILED(hr) || !pEnum) return false;

    bool tpmOk = false;
    IWbemClassObject* pObj = nullptr;
    ULONG uReturn = 0;

    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK && uReturn == 1) {
        bool enabled = false;
        bool activated = false;
        bool is20 = false;

        VARIANT vEnabled, vActivated, vSpec;
        VariantInit(&vEnabled);
        VariantInit(&vActivated);
        VariantInit(&vSpec);

        if (SUCCEEDED(pObj->Get(L"IsEnabled_InitialValue", 0, &vEnabled, nullptr, nullptr)) && vEnabled.vt == VT_BOOL) {
            enabled = (vEnabled.boolVal == VARIANT_TRUE);
        }
        if (SUCCEEDED(pObj->Get(L"IsActivated_InitialValue", 0, &vActivated, nullptr, nullptr)) && vActivated.vt == VT_BOOL) {
            activated = (vActivated.boolVal == VARIANT_TRUE);
        }
        if (SUCCEEDED(pObj->Get(L"SpecVersion", 0, &vSpec, nullptr, nullptr)) && vSpec.vt == VT_BSTR && vSpec.bstrVal) {
            std::wstring spec(vSpec.bstrVal);
            if (spec.find(L"2.0") != std::wstring::npos) {
                is20 = true;
            }
        }

        if (enabled && activated && is20) {
            tpmOk = true;
        }

        VariantClear(&vEnabled);
        VariantClear(&vActivated);
        VariantClear(&vSpec);
        pObj->Release();
    }

    pEnum->Release();
    return tpmOk;
}

int main() {
    EnableAnsiConsole();

    std::cout << Color::Cyan << Color::Bold
              << "========================================================\n"
              << "     Kevar Integrity Checker - Discord: @kevar.gg       \n"
              << "========================================================\n"
              << Color::Reset << "\n";

    bool secureBoot = CheckUefiSecureBoot();
    bool dmaGuard   = CheckDmaProtection();
    bool hvci       = CheckHvci();
    bool tpm20      = CheckTpm20();

    PrintStatusLine("UEFI Secure Boot", secureBoot);
    PrintStatusLine("DMA Protection  ", dmaGuard);
    PrintStatusLine("HVCI            ", hvci);
    PrintStatusLine("TPM 2.0         ", tpm20);

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
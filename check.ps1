$ErrorActionPreference = "SilentlyContinue"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "     Kevar Integrity Checker - Discord: @kevar.gg       " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

function Show-Check($Label, [bool]$IsOn) {
    Write-Host ("  {0,-17}: " -f $Label) -NoNewline
    if ($IsOn) {
        Write-Host "(Turned on)" -ForegroundColor Green
    } else {
        Write-Host "(Turned off)" -ForegroundColor Red
    }
}

if (-not ("KevarNative.Checker" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace KevarNative {
    public static class Checker {
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int SystemDmaGuardPolicyInformation = 202;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength
        );

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetFirmwareEnvironmentVariable(
            string lpName,
            string lpNamespace,
            out byte pBuffer,
            uint nSize
        );

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int SystemInformationClass,
            out byte SystemInformation,
            int SystemInformationLength,
            out int ReturnLength
        );

        public static bool IsSecureBootOn() {
            IntPtr hToken;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken)) {
                LUID luid;
                if (LookupPrivilegeValue(null, "SeSystemEnvironmentPrivilege", out luid)) {
                    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES {
                        PrivilegeCount = 1,
                        Luid = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    };
                    AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                }
                CloseHandle(hToken);
            }

            byte sbVal = 0;
            uint bytesRead = GetFirmwareEnvironmentVariable(
                "SecureBoot",
                "{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
                out sbVal,
                1
            );
            return bytesRead >= 1 && sbVal == 1;
        }

        public static bool IsDmaGuardOn() {
            byte policyByte = 0;
            int retLen = 0;
            int status = NtQuerySystemInformation(SystemDmaGuardPolicyInformation, out policyByte, 1, out retLen);
            return (status == 0 && policyByte != 0);
        }
    }
}
"@
}

# 1. UEFI Secure Boot (Firmware variable first, registry fallback)
$secureBoot = $false
try {
    $secureBoot = [KevarNative.Checker]::IsSecureBootOn()
} catch {}
if (-not $secureBoot) {
    $regSb = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled"
    if ($regSb.UEFISecureBootEnabled -eq 1) { $secureBoot = $true }
}

# 2. DMA Protection (NtQuerySystemInformation class 202)
$dmaOn = $false
try {
    $dmaOn = [KevarNative.Checker]::IsDmaGuardOn()
} catch {}

# 3. HVCI (Win32_DeviceGuard -> SecurityServicesRunning contains 2)
$hvciOn = $false
$dg = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard"
if ($dg -and ($dg.SecurityServicesRunning -contains 2)) {
    $hvciOn = $true
}

# 4. TPM 2.0 (Win32_Tpm -> IsEnabled_InitialValue, IsActivated_InitialValue, SpecVersion 2.0)
$tpmOn = $false
$tpm = Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName "Win32_Tpm"
if ($tpm -and $tpm.IsEnabled_InitialValue -and $tpm.IsActivated_InitialValue -and ($tpm.SpecVersion -match "2\.0")) {
    $tpmOn = $true
}

Show-Check "UEFI Secure Boot" $secureBoot
Show-Check "DMA Protection"   $dmaOn
Show-Check "HVCI"             $hvciOn
Show-Check "TPM 2.0"          $tpmOn

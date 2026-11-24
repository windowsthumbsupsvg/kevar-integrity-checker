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

# 1. UEFI Secure Boot
$secureBoot = $false
try {
    $sb = Confirm-SecureBootUEFI
    if ($sb -eq $true) { $secureBoot = $true }
} catch {
    $regSb = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled"
    if ($regSb.UEFISecureBootEnabled -eq 1) { $secureBoot = $true }
}

# 2. DMA Protection (DeviceGuard / Kernel DMA Protection registry & CIM check)
$dmaOn = $false
$dg = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard"
if ($dg -and ($dg.SecurityServicesRunning -contains 3)) {
    $dmaOn = $true
} else {
    $dmaReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity" -Name "BoostDmaProtection"
    $dmaPolicy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableKernelDmaProtection"
    if ($dmaReg.BoostDmaProtection -eq 1 -or $dmaPolicy.EnableKernelDmaProtection -eq 1) {
        $dmaOn = $true
    }
}

# 3. HVCI (Memory Integrity -> SecurityServicesRunning contains 2)
$hvciOn = $false
if ($dg -and ($dg.SecurityServicesRunning -contains 2)) {
    $hvciOn = $true
}

# 4. TPM 2.0
$tpmOn = $false
$tpm = Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName "Win32_Tpm"
if ($tpm -and $tpm.IsEnabled_InitialValue -and $tpm.IsActivated_InitialValue -and ($tpm.SpecVersion -match "2\.0")) {
    $tpmOn = $true
}

Show-Check "UEFI Secure Boot" $secureBoot
Show-Check "DMA Protection"   $dmaOn
Show-Check "HVCI"             $hvciOn
Show-Check "TPM 2.0"          $tpmOn
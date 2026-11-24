# Kevar Integrity Checker

> **Contact:** Discord `@kevar.gg`

A lightweight, **100% open-source** Windows check built for tournament hosts, competitive communities, and players to verify that important windows security features are turned on that will help combat cheating. (Using DMA and drivers)

## Is this safe?

i. Every check is a read-only (Meaning it changes nothing in you're pc and only reads if you've turned on 4 things)

ii. No obfuscation (Meaning you can see all the code and check and alter it)

---

## Why Use This in Games Without the Best Anti-Cheat?

Many competitive games do not have strong kernel-level anti-cheat systems, which makes it much easier for players to load drivers, kernel cheats, or DMA without getting caught.

When these built-in Windows security features are turned **on**—and verified before play—they shut down common cheat setups that rely on turning protections off or using cheap/weak DMA firmware:

- **Stops Many DMA Users With Weak Firmware (DMA Protection / IOMMU):** External DMA cards read and write system memory over PCIe, often using custom or cheap firmware to blend in. When Kernel DMA Protection and IOMMU memory isolation are active, DMA users whose firmware cannot bypass Windows' IOMMU and memory protections hit a wall—and trying to disable or work around those safeguards leaves the check in red.
- **Blocks Unsigned & Vulnerable Drivers (UEFI Secure Boot & HVCI):** Prevents unverified boot-time rootkits and unsigned kernel drivers from loading into protected memory. Many cheats require disabling Secure Boot or HVCI/Memory Integrity to load their drivers.
- **Adds Hardware Trust & Tamper Resistance (TPM 2.0):** Helps anchor system integrity and makes tampering or running in an untrusted state harder to hide.
- **Forces Cheats Into Detection:** Because common bypasses break when these features stay enabled, players cannot silently disable them without failing the check—giving tournament staff a clear baseline before matches start.

*(Note: This will not stop complex bypasses, this will just stop mediocre ones that have no effort put into it, so it might stop 90% of cheaters)*

---

## What It Checks

| Security Feature | Windows API / Query Used | Required Status |
| :--- | :--- | :--- |
| **UEFI Secure Boot** | `GetFirmwareEnvironmentVariableW` (`SecureBoot`) + Registry fallback | `(Turned on)` |
| **DMA Protection** | `NtQuerySystemInformation` (`SystemDmaGuardPolicyInformation`) | `(Turned on)` |
| **HVCI (Memory Integrity)** | WMI `Win32_DeviceGuard` (`SecurityServicesRunning`) | `(Turned on)` |
| **TPM 2.0** | WMI `Win32_Tpm` (`IsEnabled`, `IsActivated`, `SpecVersion`) | `(Turned on)` |

---

## Fileless PowerShell Command

If you want to check the code check out [`check.ps1`](./check.ps1) first, then run this in PowerShell to execute it via Powershell w/o any files.
```powershell
irm https://raw.githubusercontent.com/windowsthumbsupsvg/kevar-integrity-checker/main/check.ps1 | iex

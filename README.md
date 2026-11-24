# Kevar Integrity Checker

> **Contact:** Discord `@kevar.gg`

A lightweight, **100% open-source** Windows check built for tournament hosts, competitive communities, and players to verify that core Windows hardware and kernel security features are turned on before a match.

Every check is read-only and visible directly in [`kevar_integrity_checker.cpp`](./kevar_integrity_checker.cpp) and [`check.ps1`](./check.ps1)—no obfuscation, no background services, and no network connections.

---

## Why Use This in Games Without the Best Anti-Cheat?

Many competitive games do not have strong kernel-level anti-cheat systems, which makes it much easier for players to load unsigned drivers, kernel cheats, or external DMA hardware without getting caught in-game.

When these built-in Windows security features are turned **on**—and verified before play—they shut down common cheat setups that rely on turning protections off or using cheap/weak DMA firmware:

- **Stops Many DMA Users With Weak Firmware (DMA Protection / IOMMU):** External DMA cards read and write system memory over PCIe, often using custom or cheap firmware to blend in. When Kernel DMA Protection and IOMMU memory isolation are active, DMA users whose firmware cannot bypass Windows' IOMMU and memory protections hit a wall—and trying to disable or work around those safeguards leaves the check in red.
- **Blocks Unsigned & Vulnerable Drivers (UEFI Secure Boot & HVCI):** Prevents unverified boot-time rootkits and unsigned kernel drivers from loading into protected memory. Many cheats require disabling Secure Boot or HVCI/Memory Integrity to load their drivers.
- **Adds Hardware Trust & Tamper Resistance (TPM 2.0):** Helps anchor system integrity and makes tampering or running in an untrusted state harder to hide.
- **Forces Cheats Into Detection:** Because common bypasses break when these features stay enabled, players cannot silently disable them without failing the check—giving tournament staff a clear baseline before matches start.

*(Note: This is a pre-match system check, not a full anti-cheat replacement—advanced or custom firmware/bypasses can still exist, so it works best alongside match moderation and review.)*

---

## What It Checks

| Security Feature | Windows API / Query Used | Required Status |
| :--- | :--- | :--- |
| **UEFI Secure Boot** | `GetFirmwareEnvironmentVariableW` (`SecureBoot`) + Registry fallback | `(Turned on)` |
| **DMA Protection** | `NtQuerySystemInformation` (`SystemDmaGuardPolicyInformation`) | `(Turned on)` |
| **HVCI (Memory Integrity)** | WMI `Win32_DeviceGuard` (`SecurityServicesRunning`) | `(Turned on)` |
| **TPM 2.0** | WMI `Win32_Tpm` (`IsEnabled`, `IsActivated`, `SpecVersion`) | `(Turned on)` |

---

## Open-Source & Safe to Run

Players should be able to read the exact code before running anything:
- **Full Source Audit:** Inspect [`check.ps1`](./check.ps1) and [`kevar_integrity_checker.cpp`](./kevar_integrity_checker.cpp) right in this repository.
- **Read-Only Queries:** Only reads local Windows firmware, kernel policy, and WMI states—it does not change system settings, install drivers, or send data out.
- **Compile It Yourself:** You can also build the C++ version directly from [`kevar_integrity_checker.cpp`](./kevar_integrity_checker.cpp).

---

## Fileless PowerShell Command

Inspect [`check.ps1`](./check.ps1) first, then run this in PowerShell to execute it directly in memory without saving a script file to disk:

```powershell
irm [https://raw.githubusercontent.com/windowsthumbsupsvg/kevar-integrity-checker/main/check.ps1](https://raw.githubusercontent.com/windowsthumbsupsvg/kevar-integrity-checker/main/check.ps1) | iex

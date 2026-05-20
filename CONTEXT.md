# Xdows Security — Domain Glossary

## Core Concepts

- **UsbAutoScan**: A feature that automatically scans removable USB devices when they are inserted. Controlled by a single ToggleSwitch setting (default: enabled). Setting key: `UsbAutoScan`.
- **UsbScanService**: Singleton service that manages USB device scan queue, executes single-threaded file scanning, and reports progress/results via events. Lives in `Xdows-Security/Services/`.
- **UsbScanWindow**: A small popup window displayed at the bottom-right corner of the screen when a USB device is being scanned. Shows device name, progress bar, file/threat counts, and action buttons.
- **UsbScanThreatInfo**: A data record representing a single threat found during USB scanning (file path, virus name, engine name).
- **UsbScanProgressEventArgs**: Event args carrying scan progress data (drive letter, label, files scanned, threats found, completion/pause/cancel state).

## Device Detection

- **WM_DEVICECHANGE**: Windows message received via WinUIEx `WindowMessageReceived` event (not SubclassProc). Triggers on `DBT_DEVICEARRIVAL`.
- **DEV_BROADCAST_VOLUME**: P/Invoke struct for parsing volume device broadcast data. Contains `dbcv_unitmask` (bitmask: bit 0 = A:, bit 1 = B:, etc.) and `dbcv_flags`.
- **DBTF_NET**: Network drive flag. Devices with this flag are filtered out and do not trigger scanning.

## Scanning

- **Executable Extensions**: `.exe`, `.dll`, `.sys`, `.com`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.wsf`, `.msi`. Only files with these extensions are scanned on USB devices.
- **Single-threaded Scan**: USB scan processes files one at a time (no internal parallelism), independent of SecurityPage's concurrent scan architecture.
- **RunScansOnFileAsync**: A `internal static` method on `SecurityPage` that runs configured scan engines against a single file. Shared between SecurityPage's main scan and UsbScanService.
- **ScanResult**: A `internal record` on `SecurityPage` representing scan output (engine name, virus info, family info).

## UI Behavior

- **Auto-close**: UsbScanWindow auto-closes after 5 seconds when no threats are found. Remains open when threats exist.
- **Device Removal**: When a USB device is removed during scanning, the scan is automatically cancelled and the window is closed.
- **Multi-device Queue**: Each device gets its own UsbScanWindow. Scans are processed sequentially (first in, first out).
- **IsPaused**: UsbScanService exposes an `IsPaused` property for reliable pause/resume state checking (not button text comparison).

## Settings

- **UsbAutoScan setting**: Located in the Protection section of SettingsPage, after the Registry protection expander. Default value: `true`.

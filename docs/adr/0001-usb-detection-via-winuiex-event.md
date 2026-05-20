# ADR 0001: USB Device Detection via Comctl32 SetWindowSubclass

## Status

Accepted

## Context

We need to detect USB device insertion to trigger automatic scanning. The project has several options for receiving `WM_DEVICECHANGE`:

1. Use WinUIEx's `WindowManager.WindowMessageReceived` event
2. Modify the existing `SubclassProc` in `TitleBarMenu.cs`
3. Register a new `SetWindowSubclass` in MainWindow

## Decision

Register a new `SetWindowSubclass` in MainWindow (option 3).

## Rationale

- WinUIEx's `WindowMessageReceived` event only provides the `Message` property — it does **not** expose `WParam` or `LParam`, which are required to parse `DEV_BROADCAST_VOLUME` and extract the drive letter.
- The SubclassProc in TitleBarMenu.cs is tightly coupled to title bar behavior; adding device change logic there mixes concerns.
- A separate `SetWindowSubclass` call with `uIdSubclass=1` (distinct from TitleBarMenu's `uIdSubclass=0`) keeps the concerns separated while providing full access to `wParam` and `lParam`.
- The project already uses `Comctl32Library.SetWindowSubclass` and `DefSubclassProc`, so this follows existing patterns.

## Consequences

- The `_deviceChangeSubClassProc` delegate must be stored as a field to prevent garbage collection.
- No modification to TitleBarMenu.cs required.

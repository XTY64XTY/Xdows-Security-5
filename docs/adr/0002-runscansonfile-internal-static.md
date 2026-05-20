# ADR 0002: RunScansOnFileAsync as internal static on SecurityPage

## Status

Accepted

## Context

`UsbScanService` needs to call the same scan engine logic that `SecurityPage.RunScansOnFileAsync` provides. The method is currently `private` and instance-based on `SecurityPage`.

Options:
1. Change `RunScansOnFileAsync` and `ScanResult` to `internal static`
2. Extract scan logic into a separate Helper/Service class
3. Duplicate the scan logic in UsbScanService

## Decision

Change `RunScansOnFileAsync` and `ScanResult` to `internal static`.

## Rationale

- The method is already stateless — it receives all data through parameters and does not reference `this`.
- Extracting to a new class would require moving `ScanResult`, updating all call sites in SecurityPage, and potentially breaking the existing scan flow.
- Duplicating the logic creates a maintenance burden.
- The `internal` visibility restricts access to within the assembly, which is appropriate.

## Consequences

- SecurityPage's internal calls to `RunScansOnFileAsync` must be updated to use the class name (`SecurityPage.RunScansOnFileAsync`) instead of implicit `this`.
- Future refactoring could still extract this to a dedicated service class if more consumers are added.

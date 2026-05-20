# ADR 0003: USB Scan Single-Threaded Architecture

## Status

Accepted

## Context

SecurityPage uses a dual-layer concurrent architecture (Parallel.ForEachAsync + scanGate) for high-throughput scanning. USB scan could use the same pattern or remain single-threaded.

## Decision

USB scan remains single-threaded (one file at a time, sequentially).

## Rationale

- USB devices typically have slower I/O than local drives; parallelism yields diminishing returns.
- Single-threaded scanning is simpler, uses less memory, and avoids competing for scan engine resources with SecurityPage.
- The USB scan is a background convenience feature — it should not interfere with the user's primary scan workflow.
- Pause/resume/cancel are trivially implemented with a single-threaded loop.

## Consequences

- USB scans may be slower on large devices, but this is acceptable for the use case.
- If performance becomes an issue, internal parallelism can be added later without changing the public API.

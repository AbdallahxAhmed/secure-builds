# Secure Builds

Automated, independent Android app rebuilds from source on GitHub Actions with deterministic security auditing.

## What This Repo Builds and Why

This repository tracks upstream releases and rebuilds APKs with reproducible toolchains and zero AI or human effort for routine updates:

- **EntinyGram** (upstream: [`Entaytion/EntinyGram`](https://github.com/Entaytion/EntinyGram)): A privacy-focused Telegram Android client built as an StGit patchset on top of official Telegram source code.
- **XVoard** (upstream: [`ANTI-XV/XVoard`](https://github.com/ANTI-XV/XVoard)): A privacy-centric offline Android keyboard project built with Apktool.

Routine builds run without upstream secrets, telemetry tokens, or untrusted build infrastructure.

## The Deterministic Security Gate

Whenever upstream publishes an update, a deterministic scanner (`scripts/scan.py`) evaluates the diff between the new candidate ref and the last audited ref across 8 categories: new network hosts, added Android permissions, Exodus tracker signatures, build file dependencies, added/modified binaries, sensitive file paths, buildability, and commit metadata.

```
                    ┌──────────────────────────────┐
                    │ Upstream Ref Checked (cron)  │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Deterministic Security Scan │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴───────────────┐
                    │                              │
         Scan Clean (exit 0)             Flagged (exit 10)
                    │                              │
                    ▼                              ▼
      ┌───────────────────────────┐  ┌───────────────────────────┐
      │ Build, Sign, and Release  │  │ Open 'needs-review' Issue │
      │        Automatically      │  │      Halt Build Gate      │
      └───────────────────────────┘  └─────────────┬─────────────┘
                                                   │
                                            Human Review
                                                   │
                                                   ▼
                                     ┌───────────────────────────┐
                                     │ Dispatch workflow with    │
                                     │ approve_ref=<exact_ref>   │
                                     └───────────────────────────┘
```

- **Clean (`exit 0`)**: The update is built, signed, and published automatically as a new GitHub Release.
- **Flagged (`exit 10`)**: Build execution is halted. A GitHub issue titled `<App> <ref> needs review` is opened with the full markdown audit report attached.
- **Human Approval**: After reviewing the report, a maintainer approves the release by triggering the workflow manually via `workflow_dispatch` with `approve_ref = <exact ref>`.

## EntinyGram APK Flavours

Each release produces two 64-bit ARM (`arm64-v8a`) APKs:

1. **`entinygram-<ref>-arm64.apk` (Recommended)**:
   The standard pluginless flavour. Recommended for almost all users. It contains no plugin engine and enforces strict Telegram privacy enhancements.
2. **`entinygram-<ref>-arm64-plugins.apk`**:
   Includes the QuickJS / LSPlant plugin engine. **Warning**: When plugins are enabled, they run arbitrary, unsigned third-party plugin code with access to chat messages and account context. Plugins are disabled by default.

## Hardened Defaults

Builds in this repository enforce hardened configurations at compilation time:

- **EntinyGram**:
  - **Developer badges disabled**: Custom developer badges and visual flair checks are turned off.
  - **In-app updater disabled**: Background self-updater checks and APK downloads are disabled; updates are handled cleanly via GitHub releases.
- **XVoard**:
  - **No Internet Access**: The application contains no `android.permission.INTERNET` permission, ensuring keystroke data cannot leave the device over the network.

## Verifying APK Signatures

All APKs published by this repository are aligned and signed with a dedicated release key. You can verify the integrity and origin of any downloaded APK using the official Android SDK tool `apksigner`:

```bash
apksigner verify --print-certs <path-to-apk>
```

Verify that the output contains the following certificate digest:

```text
Signer #1 certificate SHA-256 digest: 4e96028c3ce915259b2a2f4af4bca7f8107dc0f9d6fdf605bd74c7c6b3547ec3
```

Formatted with colons:
`4E:96:02:8C:3C:E9:15:25:9B:2A:2F:4A:F4:BC:A7:F8:10:7D:C0:F9:D6:FD:F6:05:BD:74:C7:C6:B3:54:7E:C3`

## Roadmap

Support for reproducible, audited desktop builds of **64Gram** (desktop Telegram client) is coming next.

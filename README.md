# Secure Builds

Automated, independent app rebuilds (Android APKs and Linux desktop binaries) from source on GitHub Actions with deterministic security auditing.

## What This Repo Builds and Why

This repository tracks upstream releases and rebuilds binaries with reproducible toolchains and zero AI or human effort for routine updates:

- **EntinyGram** (upstream: [`Entaytion/EntinyGram`](https://github.com/Entaytion/EntinyGram)): A privacy-focused Telegram Android client built as an StGit patchset on top of official Telegram source code.
- **XVoard** (upstream: [`ANTI-XV/XVoard`](https://github.com/ANTI-XV/XVoard)): A privacy-centric offline Android keyboard project built with Apktool.
- **64Gram** (upstream: [`TDesktop-x64/tdesktop`](https://github.com/TDesktop-x64/tdesktop)): An unofficial desktop Telegram client for Linux (x86_64) based on official Telegram Desktop, built with hardened privacy defaults and containerized CentOS build environments.

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
- **64Gram**:
  - **Startup unsigned language pack fetch disabled**: In `Telegram/SourceFiles/storage/localstorage.cpp`, custom language pack fetching from `tdesktop-x64.github.io` is commented out (`CustomLangPack::fetchCustomLangPack`), stopping the client from downloading and applying unsigned UI string packs at launch.
  - **Radio controller endpoint cleared**: In `Telegram/SourceFiles/core/enhanced_settings.cpp`, default `http://localhost:2468` URLs for `radio_controller` are cleared to empty string `""`, ensuring group-call join/leave hashes are never POSTed anywhere.
  - **In-app updater disabled**: Automatic updates via `updates.64gr.am` are disabled (`-D DESKTOP_APP_DISABLE_AUTOUPDATE=ON`); updates are delivered cleanly via audited releases.
  - **Crash reports disabled**: Crash reporting telemetry is turned off (`-D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON`).

## Verifying APK Signatures (EntinyGram & XVoard)

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

## Verifying 64Gram Linux Tarballs

Each 64Gram release publishes a portable tarball `64gram-<tag>-linux-x86_64.tar.gz`, `SHA256SUMS`, and a GitHub build provenance attestation.

### 1. Check SHA-256 Checksum
Verify the downloaded tarball against the provided `SHA256SUMS` file:
```bash
sha256sum -c SHA256SUMS
```
Or verify against the expected hash directly:
```bash
echo "<expected_hash>  64gram-<tag>-linux-x86_64.tar.gz" | sha256sum -c -
```

### 2. Verify GitHub Build Provenance Attestation
Releases are signed using GitHub Actions build provenance attestations (`actions/attest-build-provenance`). You can verify that the binary was built in this repository's GitHub Actions pipeline from audited source code using the GitHub CLI:
```bash
gh attestation verify 64gram-<tag>-linux-x86_64.tar.gz --owner <owner>
```

# QUIC-IP / HTTP3-IP platform evidence

This document distinguishes a successful source build from a working signed
application and from device/runtime verification. The latter two cannot be
inferred from the first.

## Scope derived from this repository

The build matrix follows `.github/workflows/test.yml`, including its separate
mobile smoke, cross-minimum and browser jobs, plus
`release/dist/unixpkgs/targets.go` and the NAS architecture lists. Several extra
CPU combinations are included. NAS/container products mostly share Linux Go
cores; a Go build is not a NAS package installation test.

`./scripts/check-quic-platforms.py` records the exact command, environment,
commit, dirty state, duration, exit code and compiler log for each target. Its
normal target compiles `wgengine`, `quicip`, `quicbind`, `ipnlocal`, and `tsnet`.
The upstream special targets are intentionally narrower, as below.

| Group | Targets checked | Meaning |
| --- | --- | --- |
| Linux | amd64, 386, arm64, arm5, arm6, arm7, Geode/softfloat, mips, mipsle, mips64, mips64le, riscv64, loong64, ppc64le, s390x | Native-IP/HTTP3 core and host integration compile |
| Windows | 386, amd64, arm64 | Core compile; not a Windows installer/runtime test |
| macOS | amd64, arm64 | Core compile; local tests additionally run on arm64 |
| FreeBSD/OpenBSD | amd64 and arm64 for each | Core compile; not kernel TUN/firewall runtime tests |
| Android | 386, amd64, arm, arm64 | Core smoke compile and separate JNI/CGO binding checks |
| iOS | amd64 and arm64 | Core smoke compile; separate real iOS/simulator CGO checks |
| Browser | js/wasm | Existing `cmd/tsconnect/wasm` and CLI compile; not a claim of an OS VPN inside a browser |
| Upstream cross-minimum | plan9/amd64, aix/ppc64, solaris/amd64, illumos/amd64 | `cmd/tailscale` / `cmd/tailscaled` compile only, matching upstream's narrower check |

Total: **35 build targets**, not 35 fully tested device operating systems.
All 35 were compiled before HTTP/3 work and rerun with the HTTP/3 implementation.
The result JSON files retain their exact source revision/dirty-state provenance.

## Actual mobile binding checks

The existing Android and iOS application repositories were opened in separate
validation worktrees. Temporary Go workspaces selected this core source without
editing either original checkout or changing the production app's dependencies.

Android's actual `libtailscale` package compiled with CGO enabled for arm64,
armv7, x86 and x86_64 using the installed NDK 27.1.12297006 / API 26 toolchains.
The iOS `libtailscale` package compiled for arm64 iPhoneOS and arm64 simulator
with the installed Xcode-beta SDKs. It also passed package compilation using the
AppleTVOS SDK and an arm64 tvOS target.

These checks are stronger than only compiling a standalone portable Go package,
but they still do **not** produce signed APK/AAB/IPA artifacts or prove device
VPN permissions, sleep/wake, roaming, power behavior, or OS-version coverage.
The Android/iOS frontends remain on their existing production configuration
flows. A release must wire the new factory/configuration into app-owned storage
and update the pinned core dependency; no new mobile GUI was published here.

**Apple TV remains an explicit product-level gap.** The local `AwgScale.xcodeproj`
has no tvOS application or packet-tunnel target. An AppleTVOS-SDK library compile
does not invent such a target or validate an Apple TV app. No claim of complete
Apple TV client support is made.

## Mobile socket protection

Android's VPN service can become available after engine construction. Its
existing hooks rebind/protect magicsock sockets when the service connects.
A separately opened QUIC UDP socket would not automatically participate in that
same lifecycle. For this reason Android, iOS and browser builds require
`io=magicsock`; `io=udp` fails with a clear error. The optional public TCP site
listener is rejected there as well. This is a safety restriction, not a silent
fallback or disabling QUIC altogether.

Normal desktop/server independent UDP uses the host-provided `netns.Listener`
callback rather than opening an unprotected global socket. Embedded clients can
use `NewFactoryWithCertificate` and `wgengine.Config.Transport` without setting
process environment variables or exposing key paths.

## Runtime evidence actually available

Runtime tests in this task cover macOS arm64 local protocol/ACL/race tests and
two Linux amd64 hosts (SG and ZJG), including direct IPv4/IPv6 payload transfer
and forced DERP. Chrome's isolated test profile reads the HTTP/3 public page on
both hosts. Certificates are trusted by their exact temporary SPKI for this lab,
not by globally disabling certificate validation.

There are no physical Windows, BSD, Android, iOS or Apple TV runtime results in
this task. Use the raw reports and the build commands, not a blanket
“all-platform tested” statement, when deciding a release gate.

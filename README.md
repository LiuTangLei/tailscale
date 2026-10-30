# Tailscale with AmneziaWG and QUIC

**Current release: [v1.104.4](https://github.com/LiuTangLei/tailscale/releases/tag/v1.104.4).**

| Platform | Download |
| --- | --- |
| Linux, macOS, Windows | [CLI and daemon](https://github.com/LiuTangLei/tailscale/releases/tag/v1.104.4) |
| Android | [Signed APK](https://github.com/LiuTangLei/tailscale-android/releases/tag/v1.104.4) |
| iOS | [AwgScale IPA](https://github.com/LiuTangLei/AwgScale/releases/tag/v1.104.4) |
| OpenWrt | [IPK / APK packages](https://github.com/LiuTangLei/openwrt-tailscale-awg/releases/tag/v1.104.4) |
| Docker | `ltlei/tailscale-awg:v1.104.4` |

[Install and upgrade](https://github.com/LiuTangLei/tailscale-awg-installer#install).
The release includes native WireGuard, AWG v2/v3 and QUIC over HTTP/3.

The following overview describes the upstream Tailscale project.

## Overview

This repository contains the majority of Tailscale's open source code.
Notably, it includes the `tailscaled` daemon and
the `tailscale` CLI tool. The `tailscaled` daemon runs on Linux, Windows,
[macOS](https://tailscale.com/kb/1065/macos-variants/), and to varying degrees
on FreeBSD and OpenBSD. The Tailscale iOS and Android apps use this repo's
code, but this repo doesn't contain the mobile GUI code.

Other [Tailscale repos](https://github.com/orgs/tailscale/repositories) of note:

* the Android fork is at https://github.com/LiuTangLei/tailscale-android
* the Synology package is at https://github.com/tailscale/tailscale-synology
* the QNAP package is at https://github.com/tailscale/tailscale-qpkg
* the Chocolatey packaging is at https://github.com/tailscale/tailscale-chocolatey

For background on which parts of Tailscale are open source and why,
see [https://tailscale.com/opensource/](https://tailscale.com/opensource/).

## Using

Use the [1.104.4 release](https://github.com/LiuTangLei/tailscale/releases/tag/v1.104.4)
and the [platform installers](https://github.com/LiuTangLei/tailscale-awg-installer#install).
Mobile and OpenWrt downloads are listed above.

## Building

We always require the latest Go release, currently Go 1.27. (While we build
releases with our [Go fork](https://github.com/tailscale/go/), its use is not
required.)

```
git clone --branch v1.104.4 https://github.com/LiuTangLei/tailscale.git
cd tailscale
./build_dist.sh -o tailscale ./cmd/tailscale
./build_dist.sh -o tailscaled ./cmd/tailscaled
```

If you're packaging Tailscale for distribution, use `build_dist.sh`
instead, to burn commit IDs and version info into the binaries:

```
./build_dist.sh tailscale.com/cmd/tailscale
./build_dist.sh tailscale.com/cmd/tailscaled
```

If your distro has conventions that preclude the use of
`build_dist.sh`, please do the equivalent of what it does in your
distro's way, so that bug reports contain useful version information.

## Bugs

Please file any issues about this code or the hosted service on
[the issue tracker](https://github.com/LiuTangLei/tailscale/issues).

## Contributing

PRs welcome! But please file bugs. Commit messages should [reference
bugs](https://docs.github.com/en/github/writing-on-github/autolinked-references-and-urls).

We require [Developer Certificate of
Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin)
`Signed-off-by` lines in commits.

See [commit-messages.md](docs/commit-messages.md) (or skim `git log`) for our commit message style.

## About Us

[Tailscale](https://tailscale.com/) is primarily developed by the
people at https://github.com/orgs/tailscale/people. For other contributors,
see:

* https://github.com/tailscale/tailscale/graphs/contributors
* https://github.com/tailscale/tailscale-android/graphs/contributors

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.

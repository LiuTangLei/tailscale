#!/usr/bin/env sh
#
# Runs `go build` with flags configured for binary distribution. All
# it does differently from `go build` is burn git commit and version
# information into the binaries, so that we can track down user
# issues.
#
# If you're packaging Tailscale for a distro, please consider using
# this script, or executing equivalent commands in your
# distro-specific build system.

set -eu

go="go"
if [ -n "${TS_USE_TOOLCHAIN:-}" ]; then
	go="./tool/go"
fi

eval `CGO_ENABLED=0 GOOS=$($go env GOHOSTOS) GOARCH=$($go env GOHOSTARCH) $go run ./cmd/mkversion`

if [ "$#" -ge 1 ] && [ "$1" = "shellvars" ]; then
	cat <<EOF
VERSION_MINOR="$VERSION_MINOR"
VERSION_SHORT="$VERSION_SHORT"
VERSION_LONG="$VERSION_LONG"
VERSION_GIT_HASH="$VERSION_GIT_HASH"
EOF
	exit 0
fi

tags="${TAGS:-}"
ldflags="-X tailscale.com/version.longStamp=${VERSION_LONG} -X tailscale.com/version.shortStamp=${VERSION_SHORT}"

# build_dist.sh arguments must precede go build arguments.
while [ "$#" -gt 1 ]; do
	case "$1" in
	--extra-small)
		if [ ! -z "${TAGS:-}" ]; then
			echo "set either --extra-small or \$TAGS, but not both"
			exit 1
		fi
		shift
		ldflags="$ldflags -w -s"
		tags="${tags:+$tags,},$(GOOS= GOARCH= $go run ./cmd/featuretags --min --add=osrouter)"
		;;
	--min)
	    # --min is like --extra-small but even smaller, removing all features,
		# even if it results in a useless binary (e.g. removing both netstack +
		# osrouter). It exists for benchmarking purposes only.
		shift
		ldflags="$ldflags -w -s"
		tags="${tags:+$tags,},$(GOOS= GOARCH= $go run ./cmd/featuretags --min)"
		;;
	--strip)
		# --min overrides your flags, when you're using custom tags and want to
		# additionally strip symbols to help reduce the size, this is the easiest
		# way to do it.
		shift
		ldflags="$ldflags -w -s"
		;;
	--box)
		if [ ! -z "${TAGS:-}" ]; then
			echo "set either --box or \$TAGS, but not both"
			exit 1
		fi
		shift
		tags="${tags:+$tags,}ts_include_cli"
		;;
	*)
		break
		;;
	esac
done

# A distribution must never accidentally enable the development-only double
# encryption path. Normal peer compatibility remains native WG/AWG.
case ",$tags, $* ${GOFLAGS:-}" in
	*ts_dev_wg_over_quic*)
		echo "WG-over-QUIC is development-only; use go build with the explicit tag, not build_dist.sh" >&2
		exit 1
		;;
esac

# QUIC fixes are in the published, checksum-pinned dependency in go.mod.
# No temporary modfile, module-cache edit or source overlay is required.
# readonly also prevents a distribution build from silently changing pins.
$go build -mod=readonly ${tags:+-tags=$tags} -trimpath -ldflags "$ldflags" "$@"

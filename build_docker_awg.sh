#!/usr/bin/env sh
#
# build_docker_awg.sh
# Build and (by default) push Docker images for this AWG fork.
#
# Usage examples:
#  # build & push (default) for current tag/version:
#  ./build_docker_awg.sh
#
#  # build but do not push:
#  PUSH=false ./build_docker_awg.sh
#
#  # override repo / tags / platform:
#  REPOS=ltlei/tailscale-awg TAGS=v1.86.5 PLATFORM=linux/amd64 ./build_docker_awg.sh
#

set -eu

# Use the "go" binary from the "tool" directory (if present) as upstream scripts expect.
export PATH="$PWD"/tool:"$PATH"

# Load version vars from build_dist.sh (must exist in repo)
eval "$(./build_dist.sh shellvars)"

# defaults: tweak if you want different behaviour
PUSH="${PUSH:-true}"                                   # true -> push to registry, false -> don't push
TARGET="${TARGET:-client}"                             # client | k8s-operator | ...
REPOS="${REPOS:-ltlei/tailscale-awg}"                  # default repo to push images to (change as needed)
TAGS="${TAGS:-v${VERSION_SHORT},v${VERSION_MINOR},latest}"
BASE="${BASE:-tailscale/alpine-base:3.19}"
PLATFORM="${PLATFORM:-}"                               # default = all supported by mkctr/buildx
ANNOTATIONS="${ANNOTATIONS:-org.opencontainers.image.source=https://github.com/LiuTangLei/tailscale,org.opencontainers.image.vendor=ltlei}"

echo "build_docker_awg.sh starting with:"
echo "  TARGET = ${TARGET}"
echo "  REPOS  = ${REPOS}"
echo "  TAGS   = ${TAGS}"
echo "  PUSH   = ${PUSH}"
echo "  BASE   = ${BASE}"
echo "  PLATFORM = ${PLATFORM}"
echo ""

case "${TARGET}" in
  client)
    echo "Building client image(s) -> repos: ${REPOS}, tags: ${TAGS}"
    go run github.com/tailscale/mkctr \
      --gopaths="\
        tailscale.com/cmd/tailscale:/usr/local/bin/tailscale, \
        tailscale.com/cmd/tailscaled:/usr/local/bin/tailscaled, \
        tailscale.com/cmd/containerboot:/usr/local/bin/containerboot" \
      --ldflags="\
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --gotags="ts_kube,ts_package_container" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      --annotations="${ANNOTATIONS}" \
      /usr/local/bin/containerboot
    ;;
  k8s-operator)
    echo "Building k8s-operator image -> repos: ${REPOS}, tags: ${TAGS}"
    go run github.com/tailscale/mkctr \
      --gopaths="tailscale.com/cmd/k8s-operator:/usr/local/bin/operator" \
      --ldflags="\
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --gotags="ts_kube,ts_package_container" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      --annotations="${ANNOTATIONS}" \
      /usr/local/bin/operator
    ;;
  k8s-nameserver)
    echo "Building k8s-nameserver image -> repos: ${REPOS}, tags: ${TAGS}"
    go run github.com/tailscale/mkctr \
      --gopaths="tailscale.com/cmd/k8s-nameserver:/usr/local/bin/k8s-nameserver" \
      --ldflags=" \
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --gotags="ts_kube,ts_package_container" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      --annotations="${ANNOTATIONS}" \
      /usr/local/bin/k8s-nameserver
    ;;
  tsidp)
    echo "Building tsidp image -> repos: ${REPOS}, tags: ${TAGS}"
    go run github.com/tailscale/mkctr \
      --gopaths="tailscale.com/cmd/tsidp:/usr/local/bin/tsidp" \
      --ldflags=" \
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --gotags="ts_package_container" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      --annotations="${ANNOTATIONS}" \
      /usr/local/bin/tsidp
    ;;
  k8s-proxy)
    echo "Building k8s-proxy image -> repos: ${REPOS}, tags: ${TAGS}"
    go run github.com/tailscale/mkctr \
      --gopaths="tailscale.com/cmd/k8s-proxy:/usr/local/bin/k8s-proxy" \
      --ldflags=" \
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --gotags="ts_kube,ts_package_container" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      --annotations="${ANNOTATIONS}" \
      /usr/local/bin/k8s-proxy
    ;;
  *)
    echo "unknown target: $TARGET"
    echo "supported targets: client | k8s-operator | k8s-nameserver | tsidp | k8s-proxy"
    exit 1
    ;;
esac

echo "Done."

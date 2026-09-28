#!/usr/bin/env bash
set -e

# x64 Linux
echo "Building for linux/amd64..."
GOOS=linux GOARCH=amd64 ./build_dist.sh -o tailscaled-linux-amd64 ./cmd/tailscaled
GOOS=linux GOARCH=amd64 ./build_dist.sh -o tailscale-linux-amd64 ./cmd/tailscale

# arm64 Linux
echo "Building for linux/arm64..."
GOOS=linux GOARCH=arm64 ./build_dist.sh -o tailscaled-linux-arm64 ./cmd/tailscaled
GOOS=linux GOARCH=arm64 ./build_dist.sh -o tailscale-linux-arm64 ./cmd/tailscale

# x64 Windows
echo "Building for windows/amd64..."
GOOS=windows GOARCH=amd64 ./build_dist.sh -o tailscaled-windows-amd64.exe ./cmd/tailscaled
GOOS=windows GOARCH=amd64 ./build_dist.sh -o tailscale-windows-amd64.exe ./cmd/tailscale

# arm64 Windows
echo "Building for windows/arm64..."
GOOS=windows GOARCH=arm64 ./build_dist.sh -o tailscaled-windows-arm64.exe ./cmd/tailscaled
GOOS=windows GOARCH=arm64 ./build_dist.sh -o tailscale-windows-arm64.exe ./cmd/tailscale

# arm64 macOS
echo "Building for darwin/arm64..."
CGO_ENABLED=1 TAGS=ts_apple_no_network_extension GOOS=darwin GOARCH=arm64 \
	./build_dist.sh -o tailscaled-darwin-arm64 ./cmd/tailscaled
CGO_ENABLED=1 TAGS=ts_apple_no_network_extension GOOS=darwin GOARCH=arm64 \
	./build_dist.sh -o tailscale-darwin-arm64 ./cmd/tailscale

# x64 macOS
echo "Building for darwin/amd64..."
CGO_ENABLED=1 TAGS=ts_apple_no_network_extension GOOS=darwin GOARCH=amd64 \
	./build_dist.sh -o tailscaled-darwin-amd64 ./cmd/tailscaled
CGO_ENABLED=1 TAGS=ts_apple_no_network_extension GOOS=darwin GOARCH=amd64 \
	./build_dist.sh -o tailscale-darwin-amd64 ./cmd/tailscale

# arm64 Android
#echo "Building for android/arm64..."
#TAGS=ts_omit_systray GOOS=android GOARCH=arm64 ./build_dist.sh -o tailscaled-android-arm64 ./cmd/tailscaled
#TAGS=ts_omit_systray GOOS=android GOARCH=arm64 ./build_dist.sh -o tailscale-android-arm64 ./cmd/tailscale
echo "All builds complete."

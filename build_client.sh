#!/bin/bash

set -e

build_version=$1
if [[ -z "$build_version" ]]; then
  echo "usage: $0 <build-version>"
  exit 1
fi

package_name=client
build_folder=./dist
mkdir -p "$build_folder"
build_date=$(date +%F\ %H:%M:%S)

echo "Starting build process..."

# Подготовка флагов линковщика
ldflags="-X 'main.buildVersion=${build_version}' -X 'main.buildDate=${build_date}'"

# Для macOS (Intel)
echo "Building for darwin/amd64..."
GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build \
    -ldflags "${ldflags}" \
    -o ${build_folder}/${package_name}-darwin-amd64 \
    ./cmd/client

# Для macOS (Apple Silicon)
echo "Building for darwin/arm64..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build \
    -ldflags "${ldflags}" \
    -o ${build_folder}/${package_name}-darwin-arm64 \
    ./cmd/client

# Для Windows
echo "Building for windows/amd64..."
CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build \
    -ldflags "${ldflags}" \
    -o ${build_folder}/${package_name}-windows-amd64.exe \
    ./cmd/client

echo "Build complete!"
ls -l "$build_folder"
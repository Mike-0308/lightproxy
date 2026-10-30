#!/bin/sh
# 交叉编译全部架构（在本机执行，不需要路由器）
set -e
cd "$(dirname "$0")"

GO=${GO:-go}
VER=$(grep -m1 '^var version' admin.go | sed 's/.*"\(.*\)".*/\1/')
export CGO_ENABLED=0

mkdir -p dist
echo "构建 lightproxy v$VER（静态链接，无 CGO 依赖）"

GOOS=linux GOARCH=arm GOARM=7 $GO build -trimpath -ldflags "-s -w -X main.version=$VER" -o dist/lightproxy-linux-armv7 .
GOOS=linux GOARCH=arm64     $GO build -trimpath -ldflags "-s -w -X main.version=$VER" -o dist/lightproxy-linux-arm64 .
GOOS=linux GOARCH=amd64     $GO build -trimpath -ldflags "-s -w -X main.version=$VER" -o dist/lightproxy-linux-amd64 .
GOOS=linux GOARCH=mipsle GOMIPS=softfloat $GO build -trimpath -ldflags "-s -w -X main.version=$VER" -o dist/lightproxy-linux-mipsle .
GOOS=windows GOARCH=amd64   $GO build -trimpath -ldflags "-s -w -X main.version=$VER" -o dist/lightproxy-windows-amd64.exe .

ls -lh dist

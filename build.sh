#!/bin/sh
# 交叉编译全部架构（在本机执行，不需要路由器）
set -e
cd "$(dirname "$0")"

GO=${GO:-go}
VER=$(grep -m1 '^var version' admin.go | sed 's/.*"\(.*\)".*/\1/')
export CGO_ENABLED=0

# 可选 UPX 压缩：体积能降到三分之一，但运行时要把整个映像解压进内存，
# 常驻内存会多出约 7MB。只在闪存/磁盘吃紧、内存宽裕时才开。
#   UPX=upx ./build.sh
UPX=${UPX:-}
if [ -n "$UPX" ] && ! command -v "$UPX" >/dev/null 2>&1; then
	echo "找不到 $UPX，继续不压缩" >&2
	UPX=""
fi

LDF="-s -w -X main.version=$VER"
mkdir -p dist
echo "构建 lightproxy v$VER（静态链接，无 CGO 依赖）"

build() { # build <输出> <GOOS> <GOARCH> [GOARM|GOMIPS]
	out="dist/$1"; os=$2; arch=$3; extra=$4
	env GOOS=$os GOARCH=$arch ${extra:+$extra} $GO build -trimpath -ldflags "$LDF" -o "$out" .
	if [ -n "$UPX" ]; then
		"$UPX" -q "$out"
	fi
}

build lightproxy-linux-armv7  linux arm   GOARM=7
build lightproxy-linux-arm64  linux arm64
build lightproxy-linux-amd64  linux amd64
build lightproxy-linux-mipsle linux mipsle GOMIPS=softfloat
build lightproxy-windows-amd64.exe windows amd64

ls -lh dist

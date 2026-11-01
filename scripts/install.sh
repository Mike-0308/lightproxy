#!/bin/sh
# 轻代理 lightproxy 安装脚本（在路由器上执行，busybox sh 兼容）
#
#   一键安装（推荐，会弹出菜单）：
#     国内直连（Gitee，最快）：
#     curl -fsSL https://gitee.com/jxmike/lightproxy/raw/main/scripts/install.sh -o /tmp/lp.sh && sh /tmp/lp.sh
#     GitHub：
#     curl -fsSL https://raw.githubusercontent.com/Mike-0308/lightproxy/main/scripts/install.sh -o /tmp/lp.sh && sh /tmp/lp.sh
#   管道方式（同样能弹菜单，脚本自己读 /dev/tty）：
#     curl -fsSL https://raw.githubusercontent.com/Mike-0308/lightproxy/main/scripts/install.sh | sh
#   非交互安装（写进别的脚本里批量用）：
#     sh install.sh --yes --dir=/data/lightproxy
#   卸载：菜单里选 2，或者 sh install.sh --uninstall
#   本地二进制安装（电脑下载好再传上去）：
#     sh install.sh /tmp/lightproxy-linux-armv7
set -u

# 默认仓库；下载二进制时用，可用 LP_REPO 覆盖（owner/repo）
DEFAULT_REPO="Mike-0308/lightproxy"
# Gitee 镜像仓库：二进制优先从这里下（国内直连快），可用 LP_GITEE 覆盖
DEFAULT_GITEE="jxmike/lightproxy"
# Gitee 上对应的发行版标签；发新版时与脚本一起改
GITEE_TAG="${LP_GITEE_TAG:-v1.5.1}"
# 自定义镜像可放最前面：LP_MIRROR="https://your.mirror" sh install.sh
LP_MIRROR="${LP_MIRROR:-}"

say()  { printf '%s\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }
line() { printf '%s\n' '──────────────────────────────────────────'; }

# 交互一律走 /dev/tty：这样 `curl … | sh` 也不会去抢脚本自身的 stdin。
# 只开一次文件描述符，别用 read < /dev/tty 反复重开（EOF 后会一直读到空）。
TTYS=0
if [ -r /dev/tty ] && [ -w /dev/tty ]; then
  # 先用子 shell 探一下能不能打开：直接 exec 失败会让非交互 shell 整个退出
  if ( : </dev/tty ) 2>/dev/null; then
    { exec 3</dev/tty; } 2>/dev/null && TTYS=1
  fi
fi

REPLY=""
prompt_read() {   # $1=提示，结果存 REPLY；返回 1 表示读不到输入（EOF/无终端）
  REPLY=""
  [ "$TTYS" = 1 ] || return 1
  printf '%s' "$1"
  if ! IFS= read -r REPLY <&3; then
    [ -n "$REPLY" ] || return 1
  fi
  return 0
}

ask_yes() {       # $1=提示，默认否
  prompt_read "$1 [y/N]: " || return 1
  case "$REPLY" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

usage() {
  say "用法: sh install.sh [选项] [二进制路径]"
  say ""
  say "  不带参数            进入交互菜单（安装 / 卸载 / 退出）"
  say "  --install, -i       直接安装，不问菜单"
  say "  --uninstall, -u     卸载"
  say "  --dir=PATH          指定安装目录，如 --dir=/data/lightproxy"
  say "  --yes, -y           全部确认，不再提问"
  say "  /tmp/lightproxy-*   安装本地已下载好的二进制"
}

# ---------------------------------------------------------------- 参数
BIN_SRC=""
DIR_ARG=""
MODE=""
ASSUME_YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall|-u)  MODE=uninstall ;;
    --install|-i)    MODE=install ;;
    --yes|-y)        ASSUME_YES=1 ;;
    --dir)           shift; DIR_ARG="${1:-}" ;;
    --dir=*)         DIR_ARG="${1#--dir=}" ;;
    -h|--help)       usage; exit 0 ;;
    -*)              err "未知参数: $1（-h 看用法）"; exit 2 ;;
    *)               BIN_SRC="$1"; [ -n "$MODE" ] || MODE=install ;;
  esac
  shift
done

# ---------------------------------------------------------------- 卸载
SCAN_DIRS="/data/lightproxy /opt/lightproxy /etc/lightproxy /tmp/lightproxy"

do_remove() {   # $1=安装目录
  P="$1"
  say "卸载 $P"
  # 先摘掉开机挂钩再停进程，避免 procd 的 respawn 又把它拉起来
  if [ -f /etc/init.d/lightproxy ]; then
    /etc/init.d/lightproxy disable >/dev/null 2>&1
    /etc/init.d/lightproxy stop >/dev/null 2>&1
    rm -f /etc/init.d/lightproxy
  fi
  [ -x "$P/ctl" ] && "$P/ctl" stop >/dev/null 2>&1
  if [ -f /etc/config/firewall ] && command -v uci >/dev/null 2>&1; then
    uci -q delete firewall.lightproxy >/dev/null 2>&1
    uci -q delete firewall.lightproxy_fw >/dev/null 2>&1
    uci commit firewall >/dev/null 2>&1
  fi
  if [ -f /etc/rc.local ]; then
    sed -i "\|$P/ctl start|d" /etc/rc.local 2>/dev/null
    sed -i "\|$P/startup.sh|d" /etc/rc.local 2>/dev/null
  fi
  if [ -f /etc/crontabs/root ]; then
    sed -i "\|$P/ctl start|d" /etc/crontabs/root 2>/dev/null
  fi
  rm -rf "$P"
}

uninstall_all() {
  FOUND=""
  for P in $SCAN_DIRS; do
    [ -d "$P" ] && FOUND="$FOUND $P"
  done

  if [ -z "$FOUND" ]; then
    warn "没有找到已安装的 lightproxy"
    say "查找过的位置: $SCAN_DIRS"
    exit 0
  fi

  say "找到以下安装："
  for P in $FOUND; do say "  - $P"; done
  if [ "$ASSUME_YES" = 0 ] && [ "$TTYS" = 1 ]; then
    if ! ask_yes "确认全部卸载？配置和证书会一并删除，无法恢复"; then
      say "已取消"
      exit 0
    fi
  fi

  for P in $FOUND; do do_remove "$P"; done
  say ""
  say "已卸载。配置与证书随目录一并删除。"
  say "下次想保留配置，可以卸载前先在面板「设置 → 配置备份 → 导出备份」下载 zip。"
  exit 0
}

if [ "$MODE" = "uninstall" ]; then
  uninstall_all
fi

# ---------------------------------------------------------------- 菜单
if [ -z "$MODE" ]; then
  if [ "$TTYS" != 1 ]; then
    # 没有终端（cron、重定向）就别问，直接装
    MODE=install
  else
    line
    say " 轻代理 lightproxy 安装向导"
    line
    say "  1) 安装 / 升级"
    say "  2) 卸载"
    say "  3) 退出"
    if ! prompt_read "请选择 [1]: "; then
      say ""
      say "没有读到输入（终端已断开），已退出"
      exit 1
    fi
    case "${REPLY:-1}" in
      1|"")  MODE=install ;;
      2)     MODE=uninstall ;;
      3|q|Q) say "已退出"; exit 0 ;;
      *)     err "无效选择: $REPLY"; exit 2 ;;
    esac
    if [ "$MODE" = "uninstall" ]; then
      uninstall_all
    fi
    say ""
  fi
fi

# ---------------------------------------------------------------- 安装目录
writable() {    # $1=目录
  mkdir -p "$1" 2>/dev/null || return 1
  ( : > "$1/.probe" ) 2>/dev/null || return 1
  rm -f "$1/.probe"
  return 0
}

existing_dir() {   # 输出已安装目录，没有则返回 1
  for D in $SCAN_DIRS; do
    [ -x "$D/bin/lightproxy" ] && { printf '%s' "$D"; return 0; }
  done
  return 1
}

default_dir() {
  for D in /data/lightproxy /opt/lightproxy /etc/lightproxy; do
    [ -d "$(dirname "$D")" ] || continue
    writable "$D" && { PREFIX="$D"; return 0; }
  done
  PREFIX=/tmp/lightproxy
  writable "$PREFIX" || return 1
  return 0
}

PREFIX=""
EXIST=$(existing_dir) || EXIST=""

if [ -n "$DIR_ARG" ]; then
  if writable "$DIR_ARG"; then
    PREFIX="$DIR_ARG"
  else
    err "指定目录不可写: $DIR_ARG"
    exit 1
  fi
elif [ "$TTYS" != 1 ] || [ "$ASSUME_YES" = 1 ]; then
  # 非交互：优先沿用已有安装，其次按常规顺序挑
  if [ -n "$EXIST" ]; then PREFIX="$EXIST"; else default_dir || { err "没有可写的安装目录"; exit 1; }; fi
else
  line
  say " 选择安装目录"
  line
  say "  1) /data/lightproxy   （推荐，重启不丢）"
  say "  2) /opt/lightproxy"
  say "  3) /etc/lightproxy    （根分区空间紧张时用）"
  say "  4) 手动输入完整路径"
  say "  0) 退出"
  if [ -n "$EXIST" ]; then
    say ""
    say " 提示：检测到已安装在 $EXIST，选它即为升级（配置保留）"
  fi
  while : ; do
    if ! prompt_read "请选择 [1]: "; then say ""; say "没有读到输入，已退出"; exit 1; fi
    CH="${REPLY:-1}"
    case "$CH" in
      0|q|Q) say "已退出"; exit 0 ;;
      1) CAND="/data/lightproxy" ;;
      2) CAND="/opt/lightproxy" ;;
      3) CAND="/etc/lightproxy" ;;
      4)
        if ! prompt_read "输入完整路径（例如 /mnt/usb/lightproxy）: "; then say ""; say "没有读到输入，已退出"; exit 1; fi
        CAND="$REPLY"
        case "$CAND" in
          /*) : ;;
          *)  warn "要填绝对路径，比如 /mnt/usb/lightproxy"; continue ;;
        esac
        ;;
      *) warn "无效选择: $CH"; continue ;;
    esac
    if writable "$CAND"; then
      PREFIX="$CAND"
      break
    fi
    warn "$CAND 不可写（分区只读或权限不足），换一个"
  done
fi

FREE=$(df -k "$PREFIX" 2>/dev/null | awk 'NR==2{printf "%.1fMB", $4/1024}')
say "安装目录: $PREFIX${FREE:+（可用 $FREE）}"
mkdir -p "$PREFIX/bin" "$PREFIX/run"


# ---------------------------------------------------------------- 二进制：下载 or 本地传入
REPO="${LP_REPO:-$DEFAULT_REPO}"
# Gitee 镜像：国内直连，放在下载源第一位
GITEE_REPO="${LP_GITEE:-$DEFAULT_GITEE}"
ARCH=$(uname -m)
case "$ARCH" in
  armv7l|armv7|armv6l|arm) FILE="lightproxy-linux-armv7" ;;
  aarch64|arm64)           FILE="lightproxy-linux-arm64" ;;
  mips*)                   FILE="lightproxy-linux-mipsle" ;;
  x86_64|amd64)            FILE="lightproxy-linux-amd64" ;;
  *)                       FILE="" ;;
esac

fetch_one() {   # $1=URL $2=输出文件
  rm -f "$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --connect-timeout 12 --retry 1 --progress-bar -o "$2" "$1" && return 0
    # 部分固件的 curl 是 busybox applet，不认 --progress-bar
    curl -fsSL --connect-timeout 12 -o "$2" "$1" && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -O "$2" -T 60 "$1" && return 0
  fi
  return 1
}

download_bin() {
  BASE="https://github.com/$REPO/releases/latest/download/$FILE"
  GITEE="https://gitee.com/$GITEE_REPO/releases/download/$GITEE_TAG/$FILE"
  LIST="$GITEE
$BASE
https://ghfast.top/$BASE
https://gh-proxy.com/$BASE
https://ghproxy.net/$BASE"
  if [ -n "$LP_MIRROR" ]; then
    LIST="$LP_MIRROR
$LIST"
  fi

  say "需要下载 $FILE（约 7MB）。网速慢时会等几分钟，别急："
  say "下面有进度条；卡住不动时每 10 秒会打一个 [秒数]，说明还在等，"
  say "单个源超过 60 秒没进度会自动换下一个镜像。"
  for U in $LIST; do
    HOST=$(printf '%s' "$U" | sed 's|^[a-z]*://||; s|/.*||')
    say ""
    say "→ 尝试 $HOST"
    OUT="/tmp/$FILE.part"
    ( i=0; while : ; do sleep 10; i=$((i+10)); printf '[%ss]' "$i" >&2; done ) & WD=$!
    fetch_one "$U" "$OUT"; RC=$?
    kill "$WD" 2>/dev/null
    wait "$WD" 2>/dev/null
    SIZE=0
    if [ -f "$OUT" ]; then
      SIZE=$(wc -c < "$OUT" 2>/dev/null | tr -d ' ')
      [ -n "$SIZE" ] || SIZE=0
    fi
    if [ "$RC" = 0 ] && [ "$SIZE" -ge 3000000 ]; then
      say "✓ 下载完成（$((SIZE/1024/1024))MB）"
      BIN_SRC="$OUT"
      return 0
    fi
    if [ "$RC" = 0 ]; then
      warn "文件太小（$SIZE 字节），可能被劫持或中断"
    else
      warn "这个源连不上（返回 $RC）"
    fi
    rm -f "$OUT"
  done
  return 1
}

if [ -z "$BIN_SRC" ]; then
  if [ -z "$FILE" ]; then
    err "无法识别架构 $ARCH"
    err "请手动下载对应二进制，再执行：sh install.sh <二进制路径>"
    exit 1
  fi
  if ! download_bin; then
    err ""
    err "几个下载源都没成功，可以试试："
    err "  1) 换网络（手机热点）后重跑本脚本"
    err "  2) 电脑上下载（国内走这个）："
    err "     https://gitee.com/$GITEE_REPO/releases/download/$GITEE_TAG/$FILE"
    err "  3) 或 GitHub："
    err "     https://github.com/$REPO/releases/latest/download/$FILE"
    err "     再 scp 到路由器执行：sh install.sh /tmp/$FILE"
    exit 1
  fi
fi

if [ ! -f "${BIN_SRC:-}" ]; then
  err "用法: sh install.sh [二进制路径] [--dir=目录] [--uninstall] [--yes]"
  err "  不带参数运行会进入交互菜单"
  exit 1
fi

HINT="（未知架构）"
case "$ARCH" in
  armv7l|armv7|armv6l|arm) HINT="lightproxy-linux-armv7" ;;
  aarch64|arm64)           HINT="lightproxy-linux-arm64" ;;
  mips*)                   HINT="lightproxy-linux-mipsle" ;;
  x86_64|amd64)            HINT="lightproxy-linux-amd64" ;;
esac
say "设备架构: $ARCH"
say "对应二进制: $HINT"

# ---------------------------------------------------------------- 二进制自检
if ! cp "$BIN_SRC" "$PREFIX/bin/lightproxy.new"; then
  err "复制失败，检查 /tmp 与目标分区空间"
  exit 1
fi
chmod +x "$PREFIX/bin/lightproxy.new"
# 已经复制到目标分区，/tmp 下载的临时文件可以删了，别占闪存（用户自己传的二进制不动）
case "$BIN_SRC" in /tmp/*.part) rm -f "$BIN_SRC" ;; esac

say "试运行 …"
if ! VER=$("$PREFIX/bin/lightproxy.new" -v 2>&1); then
  err "二进制无法在本机运行（架构不匹配或文件损坏）"
  err "当前架构 $ARCH，应使用 $HINT"
  rm -f "$PREFIX/bin/lightproxy.new"
  exit 1
fi
say "  $VER"
mv "$PREFIX/bin/lightproxy.new" "$PREFIX/bin/lightproxy"

# ---------------------------------------------------------------- 配置
CFG="$PREFIX/config.json"
FIRST_RUN=0
if [ -f "$CFG" ]; then
  say "保留已有配置: $CFG"
  if ! "$PREFIX/bin/lightproxy" -c "$CFG" -check; then
    err "现有配置有误，请修正后再安装"
    exit 1
  fi
else
  say "生成默认配置 …"
  FIRST_RUN=1
  "$PREFIX/bin/lightproxy" -c "$CFG" -check || exit 1
fi

# ---------------------------------------------------------------- 控制脚本
cat > "$PREFIX/ctl" <<'CTLEOF'
#!/bin/sh
# 轻代理控制脚本。
# 单实例保证：先看 pid 文件，再按命令行兜底——防火墙 include、cron、手工调用
# 重复执行 start 都不会拉起第二个进程（第二个只会因端口占用变成白占内存的空壳）。
PREFIX="__LP_PREFIX__"
BIN="$PREFIX/bin/lightproxy"
CFG="$PREFIX/config.json"
PIDF="$PREFIX/run/lightproxy.pid"
LOG="$PREFIX/lightproxy.log"
CONSOLE="$PREFIX/console.log"
BOOTLOG="$PREFIX/boot.log"
INITD="/etc/init.d/lightproxy"
LOCK="$PREFIX/run.lock"

# 有 procd 托管（且 /etc 能持久化的真 OpenWrt）才走 init.d
has_procd() {
  [ -x "$INITD" ] && [ -f /etc/rc.common ] && [ -x /sbin/procd ] && "$INITD" enabled >/dev/null 2>&1
}

# 输出正在运行的 pid：优先 pid 文件，再按命令行兜底
find_pid() {
  if [ -f "$PIDF" ]; then
    P=$(cat "$PIDF" 2>/dev/null)
    if [ -n "$P" ] && kill -0 "$P" 2>/dev/null && grep -q lightproxy "/proc/$P/cmdline" 2>/dev/null; then
      echo "$P"; return 0
    fi
  fi
  P=$(ps w 2>/dev/null | grep "[l]ightproxy -c" | awk 'NR==1{print $1}')
  if [ -n "$P" ]; then echo "$P"; return 0; fi
  return 1
}

wait_pid() {
  i=0
  while [ $i -lt "$1" ]; do
    sleep 1
    if P=$(find_pid); then echo "$P"; return 0; fi
    i=$((i+1))
  done
  return 1
}

start() {
  if P=$(find_pid); then echo "已在运行 (pid $P)"; return 0; fi
  # 并发保护：开机时防火墙 include 与 cron 可能同时触发
  if ! mkdir "$LOCK" 2>/dev/null; then
    sleep 3
    if P=$(find_pid); then echo "已在运行 (pid $P)"; return 0; fi
    rmdir "$LOCK" 2>/dev/null
    mkdir "$LOCK" 2>/dev/null
  fi

  if has_procd; then
    "$INITD" start >/dev/null 2>&1
    if P=$(wait_pid 8); then rmdir "$LOCK" 2>/dev/null; echo "已启动 (pid $P，procd 托管)"; return 0; fi
    echo "procd 启动未成功，改用直接启动"
  fi

  mkdir -p "$PREFIX/run"
  rm -f "$PIDF"
  # 路由器固件常把 nohup 裁掉（BusyBox 精简编译），不能硬依赖。
  # 退让方案：在子 shell 里先把 HUP 设为忽略再 exec——pid 不变、SSH 断开也不会被杀。
  if command -v nohup >/dev/null 2>&1; then
    LP_LOG="$LOG" nohup "$BIN" -c "$CFG" > "$CONSOLE" 2>&1 &
  else
    ( trap '' HUP; LP_LOG="$LOG"; export LP_LOG; exec "$BIN" -c "$CFG" ) </dev/null > "$CONSOLE" 2>&1 &
  fi
  echo $! > "$PIDF"
  rmdir "$LOCK" 2>/dev/null
  if P=$(wait_pid 6); then echo "已启动 (pid $P)"; return 0; fi
  echo "启动失败，最近输出："
  tail -n 15 "$CONSOLE" 2>/dev/null
  rm -f "$PIDF"
  return 1
}

stop() {
  # 托管的实例交给 procd 停，否则它会被 respawn 又拉起来
  if has_procd; then "$INITD" stop >/dev/null 2>&1; fi
  if P=$(find_pid); then
    kill "$P" 2>/dev/null
    i=0
    while kill -0 "$P" 2>/dev/null && [ $i -lt 12 ]; do sleep 1; i=$((i+1)); done
    kill -9 "$P" 2>/dev/null
  fi
  rm -f "$PIDF"
  rmdir "$LOCK" 2>/dev/null
  echo "已停止"
}

# verify 自检：重启后如果发现服务没起来，先跑这个
verify() {
  echo "== 进程"
  if P=$(find_pid); then echo "  运行中 (pid $P)"; else echo "  未运行"; fi
  echo "== 开机自启（只应有一个）"
  N=0
  if [ -f /etc/config/firewall ] && command -v uci >/dev/null 2>&1 && uci -q show firewall.lightproxy >/dev/null 2>&1; then
    echo "  firewall include: 已挂 $(uci -q get firewall.lightproxy.path)"; N=$((N+1))
  fi
  if has_procd; then echo "  procd: 已启用 /etc/init.d/lightproxy"; N=$((N+1)); fi
  if [ -f /etc/rc.local ] && grep -q lightproxy /etc/rc.local 2>/dev/null; then
    echo "  /etc/rc.local: 已写入"; N=$((N+1))
  fi
  [ "$N" -eq 0 ] && echo "  ！一个都没有，重启后不会自启"
  [ "$N" -gt 1 ] && echo "  ！有 $N 个入口，重复但不致命（start 是幂等的），可删掉多余项"
  if [ -f /etc/crontabs/root ] && grep -q "$PREFIX/ctl start" /etc/crontabs/root 2>/dev/null; then
    echo "  cron 守护: 已注册（每 2 分钟，崩溃自愈，不会重复启动）"
  else
    echo "  cron 守护: 无（仅影响崩溃自愈）"
  fi
  echo "== 服务日志"
  if [ -f "$LOG" ]; then tail -n 6 "$LOG"; else echo "  （空）"; fi
  echo "== 直接启动的输出"
  if [ -f "$CONSOLE" ]; then tail -n 5 "$CONSOLE"; else echo "  （空）"; fi
  echo "== 开机启动记录"
  if [ -f "$BOOTLOG" ]; then tail -n 5 "$BOOTLOG"; else echo "  （空）"; fi
}

case "$1" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; start ;;
  status)  if P=$(find_pid); then echo "运行中 (pid $P)"; else echo "未运行"; fi ;;
  log)     tail -n 60 "$LOG" 2>/dev/null || tail -n 60 "$CONSOLE" ;;
  verify)  verify ;;
  *)       echo "用法: $0 {start|stop|restart|status|log|verify}" ;;
esac
CTLEOF
chmod +x "$PREFIX/ctl"
sed -i "s|__LP_PREFIX__|$PREFIX|g" "$PREFIX/ctl"

# ---------------------------------------------------------------- 开机自启
# 只挂一个能真正活过重启的入口。历史上为了"总能起来"把 init.d / 防火墙 include /
# rc.local / cron 全挂了一遍，结果重启后 procd 和 cron 各起一个，第二个抢不到端口
# 就变成白占十几 MB 的空壳。现在按固件实际情况选一个：
#   1. /etc 持久化 + 有 procd（真 OpenWrt）→ /etc/init.d（procd 托管，崩溃自动重启）
#   2. /etc/config/firewall 的 include 段 —— 小米/红米固件把 /etc 挂在 ramfs 上，
#      重启会清空 init.d、rc.d、rc.local、crontab，只有 /etc/config 是 ubifs 持久化的
#   3. /etc/rc.local（老固件兜底）
# startup.sh 自身带 5 分钟重试：开机早期网络/端口没就绪也不会一跑了之。
HOOKS=""
ETC_PERSIST=1
if grep -qE " /etc (ramfs|tmpfs) " /proc/mounts 2>/dev/null; then ETC_PERSIST=0; fi

# 先清掉历史版本留下的所有入口，避免多实例
if [ -f /etc/init.d/lightproxy ]; then
  /etc/init.d/lightproxy disable >/dev/null 2>&1
  /etc/init.d/lightproxy stop >/dev/null 2>&1
  rm -f /etc/init.d/lightproxy /etc/rc.d/S95lightproxy /etc/rc.d/K10lightproxy
fi
if [ -f /etc/rc.local ]; then
  sed -i "\|$PREFIX/startup.sh|d" /etc/rc.local 2>/dev/null
  sed -i "\|$PREFIX/ctl start|d" /etc/rc.local 2>/dev/null
fi
if [ -f /etc/crontabs/root ]; then
  sed -i "\|$PREFIX/ctl start|d" /etc/crontabs/root 2>/dev/null
fi
if [ -f /etc/config/firewall ] && command -v uci >/dev/null 2>&1; then
  uci -q delete firewall.lightproxy >/dev/null 2>&1
  uci -q commit firewall >/dev/null 2>&1
fi

cat > "$PREFIX/startup.sh" <<'STARTEOF'
#!/bin/sh
# 轻代理开机启动入口（由 /etc/config/firewall 的 include 段或 rc.local 调用）
PREFIX="__LP_PREFIX__"
BOOTLOG="$PREFIX/boot.log"

# crontab 也常挂在 ramfs 上（重启清空），所以每次开机重装一条 2 分钟守护。
# 有 procd 托管的设备不需要 —— procd 自己会 respawn。
install_watchdog() {
  [ -x /etc/init.d/lightproxy ] && /etc/init.d/lightproxy enabled >/dev/null 2>&1 && return 0
  [ -d /etc/crontabs ] || return 0
  C=/etc/crontabs/root
  touch "$C" 2>/dev/null || return 0
  grep -q "$PREFIX/ctl start" "$C" 2>/dev/null || \
    echo "*/2 * * * * $PREFIX/ctl start >/dev/null 2>&1" >> "$C"
  ps 2>/dev/null | grep -q "[c]rond" || {
    /etc/init.d/cron start >/dev/null 2>&1 || crond >/dev/null 2>&1
  }
}

(
  trap '' HUP
  i=0
  while [ $i -lt 60 ]; do
    if [ -x "$PREFIX/ctl" ] && "$PREFIX/ctl" start >>"$BOOTLOG" 2>&1; then
      # 刚起来就崩（端口没就绪）也算失败，等 3 秒复核一次
      sleep 3
      if "$PREFIX/ctl" status 2>/dev/null | grep -q 运行中; then
        echo "$(date '+%F %T') 启动成功（第 $(($i+1)) 次尝试）" >>"$BOOTLOG"
        install_watchdog
        exit 0
      fi
    fi
    sleep 5
    i=$(($i+1))
  done
  echo "$(date '+%F %T') 重试 5 分钟仍失败，放弃" >>"$BOOTLOG"
) </dev/null >>"$BOOTLOG" 2>&1 &
exit 0
STARTEOF
chmod +x "$PREFIX/startup.sh"
sed -i "s|__LP_PREFIX__|$PREFIX|g" "$PREFIX/startup.sh"

if [ "$ETC_PERSIST" = 1 ] && [ -x /sbin/procd ] && [ -f /etc/rc.common ] && [ -d /etc/init.d ]; then
  cat > /etc/init.d/lightproxy <<INITEOF
#!/bin/sh /etc/rc.common
# 轻代理 —— 唯一开机自启入口（procd 托管）
USE_PROCD=1
START=95
STOP=10

start_service() {
	mkdir -p $PREFIX/run
	procd_open_instance
	procd_set_param command $PREFIX/bin/lightproxy -c $PREFIX/config.json
	procd_set_param env LP_SUPERVISED=1 LP_LOG=$PREFIX/lightproxy.log
	procd_set_param pidfile $PREFIX/run/lightproxy.pid
	procd_set_param respawn 3600 5 5
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
INITEOF
  chmod +x /etc/init.d/lightproxy
  /etc/init.d/lightproxy enable >/dev/null 2>&1
  HOOKS="   - /etc/init.d/lightproxy（procd 托管，/etc 能持久化）"
elif [ -f /etc/config/firewall ] && command -v uci >/dev/null 2>&1; then
  uci set firewall.lightproxy=include
  uci set firewall.lightproxy.type=script
  uci set firewall.lightproxy.path="$PREFIX/startup.sh"
  uci set firewall.lightproxy.enabled=1
  uci commit firewall
  HOOKS="   - /etc/config/firewall include → startup.sh"
  if [ "$ETC_PERSIST" = 0 ]; then
    HOOKS="$HOOKS（本固件 /etc 是 ramfs，重启会清空 init.d/rc.local/crontab，只有这里是持久的）"
  fi
elif [ -f /etc/rc.local ] && [ -w /etc/rc.local ]; then
  sed -i "/^exit 0/i $PREFIX/startup.sh" /etc/rc.local 2>/dev/null
  HOOKS="   - /etc/rc.local → startup.sh"
else
  HOOKS="   - 无（需手动添加启动项）"
fi

# ---------------------------------------------------------------- 启动
"$PREFIX/ctl" stop >/dev/null 2>&1
"$PREFIX/ctl" start || warn "启动失败，请查看 $PREFIX/console.log"

# ---------------------------------------------------------------- 汇总
IPADDR=$(ip route 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
[ -z "${IPADDR:-}" ] && IPADDR=$(ifconfig 2>/dev/null | awk '/inet /{print $2; exit}' | sed 's/addr://')
[ -z "${IPADDR:-}" ] && IPADDR="<路由器IP>"

say ""
say "──────────────────────────────────────────"
say " 安装目录: $PREFIX"
say " 控制命令: $PREFIX/ctl {start|stop|restart|status|log|verify}"
say " 配置文件: $CFG"
say " 开机自启（单一入口，重复调用也不会起第二个进程）:"
printf '%b\n' "$HOOKS"
say ""
say " 管理面板: http://$IPADDR:18080/"
say " 反代入口: $IPADDR:16666（用域名访问时走 443/HTTPS）"
if [ "$FIRST_RUN" = "1" ]; then
  say " 登录密码: 见上面 -check 输出里的「管理面板账号」一行"
fi
say ""
say " 重启路由器后如果服务没起来，SSH 执行："
say "   $PREFIX/ctl verify     # 看哪些挂钩还在、启动卡在哪"
say "   $PREFIX/ctl start      # 手动拉起"
say ""
say " 接下来："
say "   1) 浏览器打开管理面板（密码见上文），在「DDNS」页填阿里云 AccessKey"
say "   2) 「端口转发」页添加规则并保存下发（反代端口会一并自动放行）"
say "   3) 「证书」页自动申请续期 Let's Encrypt 证书（DNS-01，不占 80 端口）"
say "   4) 「设置」页按需打开「HTTP 跳转」与「只允许域名访问」"
say "──────────────────────────────────────────"

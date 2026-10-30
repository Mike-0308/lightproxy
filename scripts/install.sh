#!/bin/sh
# 轻代理 lightproxy 安装脚本（在路由器上执行，busybox sh 兼容）
#
#   本地安装：  sh install.sh /tmp/lightproxy-armv7
#   一行安装：  curl -fsSL https://raw.githubusercontent.com/OWNER/lightproxy/main/scripts/install.sh | sh
#              （自动识别架构并从 GitHub Releases 下载对应二进制）
#   卸载：      sh install.sh --uninstall
set -u

# 默认仓库；一行安装时从这里下载二进制，可用环境变量 LP_REPO 覆盖（owner/repo）
DEFAULT_REPO="OWNER/lightproxy"

say()  { printf '%s\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

BIN_SRC="${1:-}"

# ---------------------------------------------------------------- 卸载
uninstall_all() {
  for P in /data/lightproxy /opt/lightproxy /etc/lightproxy /tmp/lightproxy; do
    [ -d "$P" ] || continue
    say "卸载 $P"
    [ -x "$P/ctl" ] && "$P/ctl" stop >/dev/null 2>&1
    if [ -f /etc/config/firewall ] && command -v uci >/dev/null 2>&1; then
      uci -q delete firewall.lightproxy >/dev/null 2>&1
      uci -q delete firewall.lightproxy_fw >/dev/null 2>&1
      uci commit firewall >/dev/null 2>&1
    fi
    if [ -f /etc/rc.local ]; then
      sed -i "\|$P/ctl start|d" /etc/rc.local 2>/dev/null
    fi
    if [ -f /etc/init.d/lightproxy ]; then
      /etc/init.d/lightproxy stop >/dev/null 2>&1
      /etc/init.d/lightproxy disable >/dev/null 2>&1
      rm -f /etc/init.d/lightproxy
    fi
    if [ -f /etc/crontabs/root ]; then
      sed -i "\|$P/ctl start|d" /etc/crontabs/root 2>/dev/null
    fi
    rm -rf "$P"
  done
  say "已卸载。"
  exit 0
}

if [ "$BIN_SRC" = "--uninstall" ]; then
  uninstall_all
fi

# ---------------------------------------------------------------- 一行安装：自动下载
if [ -z "$BIN_SRC" ]; then
  REPO="${LP_REPO:-$DEFAULT_REPO}"
  case "$REPO" in
    OWNER/*|*OWNER*) ;;
    *) : ;;
  esac
  ARCH=$(uname -m)
  case "$ARCH" in
    armv7l|armv7|armv6l|arm) FILE="lightproxy-linux-armv7" ;;
    aarch64|arm64)           FILE="lightproxy-linux-arm64" ;;
    mips*)                   FILE="lightproxy-linux-mipsle" ;;
    x86_64|amd64)            FILE="lightproxy-linux-amd64" ;;
    *) err "无法识别架构 $ARCH，请手动下载对应二进制后：sh install.sh <二进制路径>"; exit 1 ;;
  esac
  URL="https://github.com/$REPO/releases/latest/download/$FILE"
  say "一行安装：从 $URL 下载 …"
  BIN_SRC="/tmp/$FILE"
  if ! curl -fsSL --retry 3 -o "$BIN_SRC" "$URL" 2>/dev/null && \
     ! wget -q -O "$BIN_SRC" "$URL" 2>/dev/null; then
    err "下载失败：$URL"
    err "请检查网络，或手动下载后执行 sh install.sh $FILE"
    exit 1
  fi
fi

if [ ! -f "$BIN_SRC" ]; then
  err "用法: sh install.sh <二进制路径>"
  err "  或一行安装: curl -fsSL <install.sh 地址> | sh"
  exit 1
fi

ARCH=$(uname -m)
say "设备架构: $ARCH"
case "$ARCH" in
  armv7l|armv7|armv6l|arm) HINT="lightproxy-linux-armv7" ;;
  aarch64|arm64)           HINT="lightproxy-linux-arm64" ;;
  mips*)                   HINT="lightproxy-linux-mipsle" ;;
  x86_64|amd64)            HINT="lightproxy-linux-amd64" ;;
  *)                       HINT="（未知架构）" ;;
esac
say "对应二进制: $HINT"

# ---------------------------------------------------------------- 安装目录
PREFIX=""
for d in /data/lightproxy /opt/lightproxy /etc/lightproxy; do
  parent=$(dirname "$d")
  [ -d "$parent" ] || continue
  if mkdir -p "$d" 2>/dev/null && ( : > "$d/.probe" ) 2>/dev/null; then
    rm -f "$d/.probe"
    PREFIX="$d"
    break
  fi
done
if [ -z "$PREFIX" ]; then
  PREFIX=/tmp/lightproxy
  warn "警告：/data、/opt、/etc 都不可写，临时装到 /tmp（重启会丢失）"
fi
say "安装目录: $PREFIX"
mkdir -p "$PREFIX/bin" "$PREFIX/run"

# ---------------------------------------------------------------- 二进制自检
if ! cp "$BIN_SRC" "$PREFIX/bin/lightproxy.new"; then
  err "复制失败，检查 /tmp 与目标分区空间"
  exit 1
fi
chmod +x "$PREFIX/bin/lightproxy.new"

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
cat > "$PREFIX/ctl" <<CTLEOF
#!/bin/sh
PREFIX="$PREFIX"
BIN="\$PREFIX/bin/lightproxy"
CFG="\$PREFIX/config.json"
PIDF="\$PREFIX/run/lightproxy.pid"
LOG="\$PREFIX/lightproxy.log"
CONSOLE="\$PREFIX/console.log"
BOOTLOG="\$PREFIX/boot.log"

is_running() {
  [ -f "\$PIDF" ] || return 1
  P=\$(cat "\$PIDF" 2>/dev/null)
  [ -n "\$P" ] || return 1
  kill -0 "\$P" 2>/dev/null || return 1
  # 重启后 pid 会被别的进程复用，必须确认是自家的
  if [ -r "/proc/\$P/cmdline" ]; then
    grep -q lightproxy "/proc/\$P/cmdline" 2>/dev/null || return 1
  fi
  return 0
}

start() {
  if is_running; then echo "已在运行 (pid \$(cat \$PIDF))"; return 0; fi
  mkdir -p "\$PREFIX/run"
  rm -f "\$PIDF"
  # 路由器固件常把 nohup 裁掉（BusyBox 精简编译），不能硬依赖。
  # 退让方案：在子 shell 里先把 HUP 设为忽略再 exec——pid 不变、SSH 断开也不会被杀。
  if command -v nohup >/dev/null 2>&1; then
    LP_LOG="\$LOG" nohup "\$BIN" -c "\$CFG" > "\$CONSOLE" 2>&1 &
  else
    ( trap '' HUP; LP_LOG="\$LOG"; export LP_LOG; exec "\$BIN" -c "\$CFG" ) </dev/null > "\$CONSOLE" 2>&1 &
  fi
  echo \$! > "\$PIDF"
  sleep 1
  is_running || sleep 1
  if is_running; then
    echo "已启动 (pid \$(cat \$PIDF))"
    return 0
  fi
  echo "启动失败，最近输出："
  tail -n 15 "\$CONSOLE" 2>/dev/null
  rm -f "\$PIDF"
  return 1
}

stop() {
  if ! is_running; then echo "未在运行"; rm -f "\$PIDF"; return 0; fi
  PID=\$(cat "\$PIDF")
  kill "\$PID" 2>/dev/null
  i=0
  while kill -0 "\$PID" 2>/dev/null && [ \$i -lt 10 ]; do sleep 1; i=\$((i+1)); done
  kill -9 "\$PID" 2>/dev/null
  rm -f "\$PIDF"
  echo "已停止"
}

# verify 自检：重启后如果发现服务没起来，先跑这个
verify() {
  echo "== 进程"
  if is_running; then echo "  运行中 (pid \$(cat \$PIDF))"; else echo "  未运行"; fi
  echo "== 开机自启挂钩"
  if [ -f /etc/init.d/lightproxy ] && [ -x /etc/rc.common ]; then
    grep -q lightproxy /etc/rc.d 2>/dev/null && D="已启用" || D="已写入（enable 状态未知）"
    echo "  init.d(procd): \$D"
  else
    echo "  init.d(procd): 无"
  fi
  if [ -f /etc/config/firewall ]; then
    if grep -q "\$PREFIX/startup.sh" /etc/config/firewall 2>/dev/null; then
      echo "  firewall include: 已写入"
    else
      echo "  firewall include: 未找到（重启后可能丢失）"
    fi
  else
    echo "  firewall include: 无 /etc/config/firewall"
  fi
  if [ -f /etc/rc.local ]; then
    if grep -q "\$PREFIX/ctl start" /etc/rc.local 2>/dev/null; then
      echo "  rc.local: 已写入"
    else
      echo "  rc.local: 未写入"
    fi
  else
    echo "  rc.local: 无"
  fi
  if [ -f /etc/crontabs/root ]; then
    if grep -q "\$PREFIX/ctl start" /etc/crontabs/root 2>/dev/null; then
      echo "  cron 兜底: 已写入"
    else
      echo "  cron 兜底: 未写入"
    fi
  else
    echo "  cron 兜底: 无 /etc/crontabs/root"
  fi
  echo "== 启动脚本日志（开机重试记录）"
  if [ -f "\$BOOTLOG" ]; then tail -n 8 "\$BOOTLOG"; else echo "  （空）"; fi
  echo "== 历史报错"
  if [ -f "\$CONSOLE" ]; then tail -n 5 "\$CONSOLE"; else echo "  （空）"; fi
}

case "\$1" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; start ;;
  status)  if is_running; then echo "运行中 (pid \$(cat \$PIDF))"; else echo "未运行"; fi ;;
  log)     tail -n 60 "\$LOG" 2>/dev/null || tail -n 60 "\$CONSOLE" ;;
  verify)  verify ;;
  *)       echo "用法: \$0 {start|stop|restart|status|log|verify}" ;;
esac
CTLEOF
chmod +x "$PREFIX/ctl"

# ---------------------------------------------------------------- 开机自启
# 不赌单一入口，能挂的都挂上（每个都幂等），重启后总有活着的：
#   1. 真 OpenWrt（有 procd）→ /etc/init.d
#   2. 防火墙 include → /etc/config/firewall（小米固件最可靠的持久化点）
#   3. /etc/rc.local
#   4. cron 兜底：哪怕上面全部丢失，每 2 分钟也会把服务拉起来
# startup.sh 自身带 5 分钟重试：开机早期 /data 可能还没挂载，第一次跑不到也不放弃。
HOOKS=""

cat > "$PREFIX/startup.sh" <<STARTEOF
#!/bin/sh
# 开机启动入口（由 firewall include / rc.local / init.d 调用）
BOOTLOG="$PREFIX/boot.log"
(
  trap '' HUP
  i=0
  while [ \$i -lt 60 ]; do
    if [ -x $PREFIX/ctl ] && $PREFIX/ctl start >>"\$BOOTLOG" 2>&1; then
      echo "\$(date '+%F %T') 启动成功（第 \$((\$i+1)) 次尝试）" >>"\$BOOTLOG"
      exit 0
    fi
    sleep 5
    i=\$((\$i+1))
  done
  echo "\$(date '+%F %T') 重试 5 分钟仍失败，放弃" >>"\$BOOTLOG"
) </dev/null >>"\$BOOTLOG" 2>&1 &
exit 0
STARTEOF
chmod +x "$PREFIX/startup.sh"

# 1) procd
if [ -x /sbin/procd ] && [ -f /etc/rc.common ] && [ -d /etc/init.d ]; then
  cat > /etc/init.d/lightproxy <<INITEOF
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=95
STOP=10

start_service() {
	procd_open_instance
	procd_set_param command $PREFIX/bin/lightproxy -c $PREFIX/config.json
	procd_set_param env LP_SUPERVISED=1 LP_LOG=$PREFIX/lightproxy.log
	procd_set_param respawn 3600 5 5
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
INITEOF
  chmod +x /etc/init.d/lightproxy
  /etc/init.d/lightproxy enable >/dev/null 2>&1
  HOOKS="$HOOKS\n   - /etc/init.d/lightproxy（procd）"
fi

# 2) 防火墙 include
if [ -f /etc/config/firewall ] && command -v uci >/dev/null 2>&1; then
  uci set firewall.lightproxy=include
  uci set firewall.lightproxy.type='script'
  uci set firewall.lightproxy.path="$PREFIX/startup.sh"
  uci set firewall.lightproxy.enabled='1'
  uci commit firewall
  HOOKS="$HOOKS\n   - /etc/config/firewall include → startup.sh"
fi

# 3) rc.local
if [ -f /etc/rc.local ] && [ -w /etc/rc.local ]; then
  if ! grep -q "$PREFIX/ctl start" /etc/rc.local 2>/dev/null && \
     ! grep -q "$PREFIX/startup.sh" /etc/rc.local 2>/dev/null; then
    sed -i "/^exit 0/i $PREFIX/startup.sh" /etc/rc.local 2>/dev/null
  fi
  HOOKS="$HOOKS\n   - /etc/rc.local"
fi

# 4) cron 兜底（busybox crond 每分钟重读 crontabs）
if [ -d /etc/crontabs ] && [ -w /etc/crontabs/root ] || { [ -d /etc/crontabs ] && touch /etc/crontabs/root 2>/dev/null; }; then
  if ! grep -q "$PREFIX/ctl start" /etc/crontabs/root 2>/dev/null; then
    echo "*/2 * * * * $PREFIX/ctl start >> $PREFIX/boot.log 2>&1" >> /etc/crontabs/root
  fi
  # crond 没跑就拉起来
  if ! ps 2>/dev/null | grep -v grep | grep -q crond; then
    /etc/init.d/cron start >/dev/null 2>&1 || crond >/dev/null 2>&1
  fi
  HOOKS="$HOOKS\n   - cron（每 2 分钟兜底）"
fi

[ -n "$HOOKS" ] || HOOKS="\n   - 无（需手动添加启动项）"

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
say " 开机自启（多重保险，全部幂等）:"
printf '%b\n' "$HOOKS"
say ""
say " 管理面板: http://$IPADDR:8081/"
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

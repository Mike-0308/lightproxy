# 轻代理 LightProxy

**许可证：MIT** —— 可自由使用、修改、商用、再分发，保留版权声明即可（详见文末 License）。

给内存吃紧的路由器用的 **反向代理 + 端口转发 + 阿里云 DDNS + 自动证书**。软件为本人自用，让AI针对小米CR8808设计，其它机型未经测试，发现的友友可以自测。

- 单文件，静态链接，零依赖：约 7MB（armv7）
- 常驻内存实测 17~22MB，空闲时更低
- 自带 Web 管理面板，配置热更新，改规则不用重启
- 纯 Go 标准库实现，没有第三方依赖，阿里云签名照官方算法手写（单元测试与官方 SDK 逐字节对拍）

为小内存路由器（256MB 级别）设计，兼容任何有 SSH 的 Linux 设备。

## 功能

**反向代理**
- 按「域名 + 路径前缀」匹配，路径前缀自动从上游剥离
- 支持泛域名 `*.example.com`、通配 `*`
- WebSocket（101 透传）、SSE、大文件流式转发
- 保留原始 Host、自定义/删除请求头、跳过上游证书校验
- HTTPS：证书目录自动放在安装目录的 `certs/`，按 SNI 自动选证书，支持多域名；开启 HTTPS 不用填任何证书路径
- HTTP → HTTPS 自动跳转（仅域名访问跳转，IP 直连不跳；外网映射端口非 443 时带上端口）。
  同一端口上的明文 `http://` 已经自动处理，**默认不需要再开一个 HTTP 端口**；
  想额外用 80 收 HTTP 才需要填「额外 HTTP 监听地址」，而 80 通常被路由器管理后台占用，抢了会让路由器 Web 打不开
- 手滑写成 `http://域名:端口` 也不会卡住：**同一个端口**上会识别出明文请求并 307 到 `https://`，
  不再出现 `Client sent an HTTP request to an HTTPS server.`，地址栏回车就能进去（IP 直连不跳转，内网调试照常）

**端口转发（内核 DNAT + IPv6 用户态裸转发）**
- 面板管规则，写入 iptables（fw3/fw4 都可用）或 nftables，转发由内核完成，不占进程内存
- TCP / UDP / 两者，支持内网回环（hairpin，内网设备用公网 IP 也能访问）
- **IPv6 用户态裸转发（`forward.v6Forward`，默认开）**：无公网 IPv4 的家宽域名只有 AAAA，
  而内核做不了「IPv6 → IPv4」的跨协议族 NAT，程序会在本机 `[::]:端口` 监听（双栈），
  把外网 IPv6 连接原样转给内网目标——RDP、SSH 等任意 TCP/UDP 服务都能用 `域名:端口` 访问。
  映射端口会一并写进 IPv6 INPUT 放行（`LP_IN6`）；规则端口与反代/面板端口冲突时整条跳过并在日志提醒
- **转发端口敲门放行（`security.knockForward`，需先配安全入口）**：裸转发是原样搬运字节，
  扫描器连上就能和后端服务对话、识别出这是 RDP 还是 SSH。开启后转发的端口不再见人就应答——
  只有浏览器先通过一次安全入口的来源网络才放行（IPv6 按 /64 记录，IPv4 按单个 IP，7 天有效，
  与入口票据同有效期），名单外的连接**接受后立即断开、一个字节不回**，扫描器拿不到任何协议指纹。
  出门时在要连 RDP 的那台设备上开一次 `https://域名:端口/<入口>`，mstsc 就能连；换网络后重开一次即可
- 规则只写进自家链（`LP_FWD` / `LP_ACL` / `LP_IN` / `LP_MASQ`），不动系统已有规则，失败自动清空回滚，不会把路由器搞断网
- 自动放行：FORWARD 转发与回程连接（精确到目标地址+端口），并把**反代监听端口**写进 INPUT 放行（IPv4 与 IPv6 都开，且不依赖端口转发功能是否开启）——路由器自带防火墙全开时，也只有这些端口能从外网进来；管理面板端口永远不会被放行
- 自动生成开机脚本并挂到 `/etc/config/firewall` 的 include（uci），重启路由规则不丢
- 需要以 root 运行（iptables 需要 CAP_NET_ADMIN）

**只允许域名访问（安全）**
- 打开后，**外网**用 IP（v4/v6）直连反代端口或面板端口一律 403，只认域名
- **内网（192.168.x / 10.x / 172.16-31.x / fe80:: / fd00::）和本机不受影响**，用 IP 直连照常用——内网没有安全风险
- 面板藏在反代后面也能正常进（自动识别 `X-Forwarded-Host`）
- 与路由器自带的 IPv6 防火墙配合：防火墙挡端口，这一层挡「外网 IP:端口 直接打开」

**安全入口（安全）**
- 设置页填一个只有你知道的路径，例如 `/x7k2m`，外网就只能走 `https://域名:端口/x7k2m`
- 直接打开 `https://域名:端口/` 返回**最普通的 404**，不暴露这里是反向代理——端口扫描器扫到了也进不来
- 入口前缀会自动剥离，面板和其它应用看到的仍然是 `/`、`/api/...` 这些自己的路径
- 进过一次就种一张 7 天有效的通行票据（`lp_entry`），页面里的 `/static`、`/api` 等绝对路径资源照常加载
- 改入口或改面板密码，旧票据立即失效；**内网与本机始终可以直接访问**，不会把自己锁在外面
- 域名本身是公开的（证书透明日志里就有），这一层是「只允许域名访问」之外的又一道保险

**配置备份**- 设置页一键导出为一个 zip 包：配置 + 证书 + 证书私钥 + ACME 账户密钥（含 AccessKey，注意保管）
- 导入即恢复配置与证书并热加载，换机器/重装后直接可用，不用重新签发；导入前先校验，不合法的包不生效

**自动证书（ACME DNS-01）**
- 支持 Let's Encrypt（含测试环境）与 ZeroSSL，CA 地址可自定义
- DNS-01 验证走阿里云解析：自动添加/清理 TXT 记录，不占 80 端口、不与反代抢路径、支持泛域名
- AccessKey 留空自动复用 DDNS 的（运行时复用，改 DDNS 密钥这里跟着变）
- 证书自动保存在安装目录的 `certs/`（如 `/data/lightproxy/certs`），不用填目录；签发后自动热加载，后台每小时巡检，剩余有效期低于阈值（默认 30 天）自动续
- 「检查配置」可提前验证 AccessKey 与每个域名能否找到解析，避免签发一半才失败

**DDNS（阿里云）**
- A / AAAA 记录，多条域名；支持泛解析（`*`）与多级前缀
- 「域名」栏可以直接写 `*.example.com` 这样的完整域名，保存时自动拆成主域名 + 主机记录
- 公网 IP 两种获取方式：在线接口查询（默认）/ 读网卡地址（PPPoE 拨号）
- 值没变不写 API，只在变化时新增/更新（对阿里云接口零浪费）
- 「测试 AccessKey」「检测公网 IP」「立即同步」一键排查

**管理面板**（默认 `http://路由器IP:18080/`）
- 概览：运行时长、内存、请求计数，反代/DDNS/端口转发/证书四块状态一屏看完
- 反代规则 / 端口转发 / DDNS / 证书全部可视化编辑，保存即生效
- 配置备份：设置页一键导出 zip（配置 + 证书），导入前先校验、不合法不生效，可直接迁移到别的设备
- 内存环形日志（最近 600 条，不占闪存）
- 一键重启、证书热重载

## 安装

路由器 SSH 里执行，会弹出向导（先选做什么，再选装到哪）：

**国内推荐用 Gitee（直连，不用镜像绕路）：**

```bash
curl -fsSL --connect-timeout 10 --max-time 60 https://gitee.com/jxmike/lightproxy/raw/main/scripts/install.sh -o /tmp/lp.sh && sh /tmp/lp.sh
```

**GitHub 版（海外或已有代理）：**

```bash
curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/Mike-0308/lightproxy/main/scripts/install.sh -o /tmp/lp.sh && sh /tmp/lp.sh
```

> 两条命令拿到的是同一份脚本，只下载 21KB，加了超时，网络不通会立刻报错而不是一直卡着。
> 脚本内部再下载 7MB 二进制时，**优先走 Gitee**，连不上才依次退回 GitHub 和 `ghfast.top` / `gh-proxy.com` / `ghproxy.net` 镜像，全程不用你干预。
>
> 想强制指定某个源：`LP_MIRROR=https://your.mirror sh /tmp/lp.sh`；
> Gitee 仓库换成自己的：`LP_GITEE=你的用户名/lightproxy sh /tmp/lp.sh`。

向导长这样：

```
──────────────────────────────────────────
 轻代理 lightproxy 安装向导
──────────────────────────────────────────
  1) 安装 / 升级
  2) 卸载
  3) 退出
请选择 [1]:
```

选完再选安装目录：

```
 选择安装目录
  1) /data/lightproxy   （推荐，重启不丢）
  2) /opt/lightproxy
  3) /etc/lightproxy    （根分区空间紧张时用）
  4) 手动输入完整路径
  0) 退出
```

手动输入支持任意绝对路径（比如 `/mnt/usb/lightproxy`），会先校验目录可写再继续。

之后脚本自动完成：识别架构 → 下载对应二进制 → 试运行自检 → 写默认配置 → 挂开机自启 → 启动。

**下载 7MB 左右，网慢要等几分钟**，脚本会把话说清楚：有进度条；卡住时每 10 秒打一个 `[秒数]` 表示还在等；某个源连不上自动换镜像（Gitee → GitHub → `ghfast.top` → `gh-proxy.com` → `ghproxy.net`），不用你干预。

> 之前装过的话，向导会提示「检测到已安装在 xxx」，选它即为升级，配置和证书都保留。

管道方式也能弹菜单（脚本从 `/dev/tty` 读输入，不抢 stdin）：

```bash
curl -fsSL https://raw.githubusercontent.com/Mike-0308/lightproxy/main/scripts/install.sh | sh
```

不想交互（写进别的脚本里批量跑）：

```bash
sh /tmp/lp.sh --yes --dir=/data/lightproxy
```

全部参数（`sh /tmp/lp.sh -h` 也能看）：

| 参数 | 作用 |
|---|---|
| 无参数 | 进入交互向导 |
| `--install` / `-i` | 直接安装，跳过菜单 |
| `--uninstall` / `-u` | 卸载（等价菜单选 2） |
| `--dir=/path` | 指定安装目录 |
| `--yes` / `-y` | 全部确认，不再提问 |
| `/tmp/lightproxy-armv7` | 安装本地已下载好的二进制 |

本地安装（电脑下载好再传上去，适合路由器连不上外网）：

```bash
scp dist/lightproxy-linux-armv7 scripts/install.sh root@192.168.10.1:/tmp/
ssh root@192.168.10.1 "sh /tmp/install.sh /tmp/lightproxy-linux-armv7"
```

浏览器打开 `http://192.168.10.1:18080/`，密码在安装输出的「管理面板账号」一行。

**只更新控制脚本（不用重传二进制）**：路由器上已有的 `/data/lightproxy/bin/lightproxy` 可以直接当安装源复用——

```bash
scp scripts/install.sh root@192.168.10.1:/tmp/
ssh root@192.168.10.1 "sh /tmp/install.sh /data/lightproxy/bin/lightproxy"
```

日常管理（SSH 里）：

```bash
/data/lightproxy/ctl status     # 运行状态
/data/lightproxy/ctl restart    # 改完配置后重启
/data/lightproxy/ctl log        # 看日志
/data/lightproxy/ctl verify     # 重启后服务没起来？看自启挂钩与启动日志
```

## 卸载

向导里选 **2** 就行。也可以直接命令行：

```bash
sh /tmp/lp.sh --uninstall

# 没传过脚本时，一行远程卸载
curl -fsSL https://raw.githubusercontent.com/Mike-0308/lightproxy/main/scripts/install.sh | sh -s -- --uninstall
```

会先列出找到的所有安装目录（`/data/lightproxy`、`/opt/lightproxy`、`/etc/lightproxy`、`/tmp/lightproxy`），确认后先摘掉开机挂钩再停进程（避免 procd 的 respawn 又拉起来），最后删除目录。

如需保留配置，卸载前先在面板「设置 → 配置备份 → 导出备份」下载一份 zip。

## 开机自启

不赌单一入口，安装时能挂的钩子全部挂上（彼此幂等），重启后总有活着的：

1. 真 OpenWrt（有 procd）→ `/etc/init.d/lightproxy`
2. 防火墙 include → `/etc/config/firewall`（`/etc` 重启还原的固件上，这是最可靠的持久化点）
3. `/etc/rc.local`
4. **cron 兜底**：哪怕上面全部丢失，每 2 分钟也会把服务拉起来

启动脚本自带 5 分钟重试并落盘 `$PREFIX/boot.log`：开机早期 `/data` 可能还没挂载，第一次跑不到也会自动再来。

重启路由器后如果服务没起来：

```bash
/data/lightproxy/ctl verify    # 看哪些挂钩还在、启动卡在哪一步
/data/lightproxy/ctl start     # 手动拉起
```

## 让外网访问到（推荐配置流程）

DDNS 只解决「域名指向你的 IP」，还要把端口放进来。推荐这样配：

1. **路由器后台做端口映射**：比如把外网 `8443` 映射到路由器自身 `16666`（反代监听端口）。
   不想用后台的话，也可以用 **面板 → 端口转发**：加一条 `8443 → 路由器LAN IP:16666` 的规则，
   「保存并下发」后规则持久化、重启自动恢复。
2. **反代监听端口会自动放行（IPv4 + IPv6）**：无论是否使用面板的端口转发功能，lightproxy 都会把自己的
   监听端口（反代 `16666`，开了 HTTP 跳转再加跳转端口）写进 INPUT 放行，并做成开机脚本
   挂到防火墙配置上。小米等固件的端口映射只放行原始外网端口、不放行转换后的本机端口，
   这一步就是补上它的。IPv6 没有 NAT，外网直接打到路由器自身，而 fw3 的 `zone_wan_input`
   末尾是 REJECT——所以 v6 也要单独放行（`LP_IN6` 链），否则只有 AAAA 记录时表现为
   「域名能解析、端口也映射了，就是打不开」。管理面板端口永远不会被放行。
3. **路由器自带防火墙**（如 IPv6 防火墙）可以放心全开——只放行了上述端口。
4. **面板 → 设置 → 访问控制**：打开「只允许域名访问」，外网拿 IP 扫不到你的服务（内网不受影响）。
   同时建议加一条反代规则把面板藏在域名后面：`panel.example.com → http://127.0.0.1:18080`。
5. **再加一道安全入口**（可选但强烈建议）：设置页「安全入口」填 `/x7k2m` 之类，
   之后外网只能走 `https://panel.example.com:8443/x7k2m`，直接开根路径是 404。域名本身在证书透明日志里是公开的，
   这一步让扫到域名+端口的人也进不来。内网访问不受影响。
6. 外网用 `https://nas.example.com:8443` 访问；公网端口非 443 时记得在「设置 → HTTPS → 公网端口」
   填实际外网端口，HTTP 跳转才能跳对地方。用 `http://` 写错了也不要紧，同一端口会 307 到 `https://`。

也可以 SSH 手工命令（与上面自动放行等效）：

```bash
iptables -t nat -A PREROUTING -i pppoe-wan -p tcp --dport 443 -j DNAT --to-destination 192.168.31.1:8443
iptables -t nat -A PREROUTING -i pppoe-wan -p tcp --dport 80  -j DNAT --to-destination 192.168.31.1:16666
iptables -A INPUT -p tcp -m multiport --dports 16666,8443 -j ACCEPT
```

管理面板 18080 **不要**映射到外网（程序层也不会自动放行它）。

## 配置 DDNS

1. 阿里云控制台 → RAM 访问控制 → 创建子用户，**只授予 `AliyunDNSFullAccess`**，生成 AccessKey
2. 面板 → DDNS → 填 AccessKey ID / Secret → 添加记录（主域名 `example.com`，主机记录 `home` 或 `*`，类型 `A`）
3. 「测试 AccessKey」确认密钥可用 → 「检测公网 IP」确认能拿到地址 → 保存
4. 等一个检测周期，或点「立即同步」

PPPoE 拨号且运营商不给公网 IPv4 时，可加一条 AAAA 记录走 IPv6，IP 获取方式选「读取网卡地址」并填 `pppoe-wan`。

## 配置 HTTPS

**自动证书（推荐）**：面板 → 证书 → 开启，填邮箱和域名，点「检查配置」确认域名能匹配到阿里云解析，再点「立即签发」。
证书自动写进安装目录的 `certs/`，然后到设置页把 HTTPS 开关打开即可——**不用填任何证书路径**，签发/续期后自动热加载。

手动放证书也可以：把 nginx 格式的 `nas.example.com.crt` + `.key` 直接丢进 `certs/` 目录，
再打开 HTTPS 开关（或在面板点「重载证书」），按域名 SNI 自动匹配。

开启 HTTPS 时如果还没有证书，服务会先以 HTTP 运行（不会起不来），证书就绪后重启一次即切到 HTTPS。

目录里可以放多张证书，按访问的域名（SNI）自动匹配；没匹配到且没配默认证书时会握手失败（这是特性，防止回源错证书）。

## 配置端口转发

面板 → 端口转发 → 开启 → 添加规则（如 `远程桌面 / TCP / 23323 → 192.168.31.190:3389`）→ 「保存并下发」。

- 外网访问：有公网 IPv4 走内核 DNAT；只有 IPv6 时走用户态裸转发，同样 `域名:外网端口` 直达
- **外网端口不要填反代监听端口**（如 8686）：那个端口归反向代理，撞上的规则会被跳过，日志有提醒
- 「生效状态」卡片会显示后端（iptables/nftables）、生效条数、IPv6 裸转发端口、放行端口、开机持久化结果
- 下发失败会自动回滚并在面板显示原因（最常见是没用 root 运行）
- 「清空内核规则」只清本工具自己的链，不影响路由器原有转发

## 配置字段速查

| 字段 | 说明 |
|---|---|
| `listen` | 反代监听，默认 `:16666`（避开 8080/8081，防止占用路由器管理后台端口） |
| `admin.listen` / `admin.pass` | 面板地址（默认 `0.0.0.0:18080`）与密码；`pass` 留空则免登录（仅限内网） |
| `tls.redirect` | HTTP 自动 301 到 HTTPS（仅域名访问跳转，IP 直连不跳转）；`httpListen` 为空时此项会被自动关掉 |
| `tls.httpListen` | **一般留空**：反代端口上的 `http://` 会自动 307 到 `https://`，不需要额外端口。填了才会另开一个端口收 HTTP（如 `:8080`）；填成反代端口本身也不会重复监听、不会报端口占用 |
| `tls.publicPort` | 外网访问的 HTTPS 端口（非 443 时跳转会带上），默认 443 |
| `security.requireDomain` | 外网只允许域名访问（IP 直连 403）；内网与本机始终放行 |
| `security.allowLoopback` | 回环豁免，允许 127.0.0.1 / ::1 访问面板（默认开） |
| `security.extraHosts` | 额外放行的域名（逗号分隔） |
| `security.entryPath` | 安全入口路径，如 `/x7k2m`；填了以后外网必须带这个前缀，否则 404。留空不启用 |
| `security.knockForward` | 转发端口敲门放行：访问过安全入口的来源网络才能连用户态转发的端口，其余连接秒断（需 entryPath，默认关） |
| `proxy[].hosts` | 域名列表，支持 `*.example.com`、`*` |
| `proxy[].path` | 路径前缀，`/` 或 `/api`；转发给上游时会剥离 |
| `proxy[].target` | 上游地址，如 `http://192.168.31.10:5000` |
| `proxy[].preserveHost` | 透传浏览器原始 Host（反代路由器后台/NAS 需要勾） |
| `proxy[].headers` | 追加请求头，支持 `{client}` `{host}` `{scheme}` 变量 |
| `tls.certDir` | 证书目录，留空自动用 `<配置目录>/certs`；`<域名>.crt` + `<域名>.key`，按 SNI 匹配 |
| `acme.enable/domains/email` | 自动证书：开启、域名列表（支持 `*.example.com`）、联系邮箱 |
| `acme.ca` | `letsencrypt`（默认）/ `letsencrypt-staging` / `zerossl` / 自定义 directory URL |
| `acme.certDir` | 签发结果写入目录，留空继承 `tls.certDir`（即自动目录） |
| `acme.renewDays` | 剩余多少天进入续期，默认 30（7~60） |
| `acme.accessKeyId/Secret` | 留空自动复用 `ddns` 的密钥（仅运行时，不写回配置） |
| `forward.enable` | 端口转发总开关；关闭时启动会清理自家链 |
| `forward.backend` | `auto`（默认）/ `iptables` / `nftables` / `off` |
| `forward.hairpin` | 内网回环（MASQUERADE），内网设备用公网 IP 访问时需要 |
| `forward.v6Forward` | IPv6 用户态裸转发开关，默认开；关掉后只有 IPv4 DNAT 生效 |
| `forward.rules[].proto` | `tcp` / `udp` / `both` |
| `forward.rules[].port` | 外网端口；同协议同端口不可重复 |
| `forward.rules[].toHost` | 目标 IPv4（内核 DNAT 不做域名解析） |
| `ddns.interval` | 检测间隔秒数，最小 60 |
| `ddns.ipMode` | `api` 在线查询 / `interface` 读网卡 |
| `runtime.memLimitMB` | Go 堆软上限，默认 32；内存紧张可降到 24 |
| `runtime.accessLog` | 访问日志，默认关（闪存写入友好，调试时再开） |

环境变量：`LP_CONFIG` 指定配置路径；`LP_LOG` 指定日志文件；`LP_SUPERVISED=1` 告诉程序由 init 守护（重启接口直接退出而不是 exec）。

## 排查

| 现象 | 处理 |
|---|---|
| 面板打不开 | `netstat -lntp \| grep 18080` 看端口；`/data/lightproxy/ctl status` 看进程；`console.log` 看报错 |
| 重启路由后服务没起来 | `/data/lightproxy/ctl verify` 看哪些自启挂钩还在、启动卡在哪；`ctl start` 手动拉起 |
| DDNS 报 SignatureDoesNotMatch | 路由器时钟不准，确认 NTP 已同步（签名对时间敏感） |
| DDNS 报 InvalidAccessKeyId | AccessKey 填错或被禁用 |
| DDNS 报 InvalidDomainName.NoExist | 「域名」栏要填**主域名**（如 `example.com`），泛解析把 `*` 填在「主机记录」栏；也可以直接在域名栏写 `*.example.com`，保存时自动拆分 |
| 域名解析不生效 | `nslookup home.example.com` 看 TTL；阿里云解析页确认记录值 |
| 端口转发报「iptables 不可用」 | 用 root 运行；或 `forward.backend` 改 `nftables` 试试 |
| 端口转发下发失败已回滚 | 看「生效状态」里的错误详情；确认目标 IP 可 ping、外网端口没被系统占用 |
| 转发规则重启后丢了 | 看「生效状态」的持久化说明；一般由 `/etc/config/firewall` 的 `lightproxy_fw` include 恢复，cron 每 2 分钟兜底 |
| 证书报「找不到对应的域名」 | 「检查配置」看每个域名的 zone 匹配；域名必须托管在同一个阿里云账号 |
| 证书验证超时 | DNS 传播慢，稍等几分钟重新点「立即签发」；刚改过解析的域名等 TTL 过期 |
| 打开页面显示 403「只允许域名访问」 | 访问方式不对：用反代规则里配置的域名访问；救急可 SSH 改 `config.json` 里 `security.requireDomain=false` 后 `ctl restart` |
| 外网访问全是 404（内网正常） | 开了安全入口，地址后面要带 `security.entryPath`；忘记路径就看 `config.json`，或内网访问面板改掉 |
| 浏览器提示 Client sent an HTTP request to an HTTPS server | 1.1.0 起已自动 307 到 https，不用手改地址；若仍出现说明跑的是旧版本 |
| 外网访问不通 | 先确认 DDNS 生效，再确认端口转发/防火墙，最后确认证书 |
| 内存占用高 | `cat /proc/$(pidof lightproxy)/status \| grep VmRSS`；并发大时属正常，空闲应 <25MB |
| 启动即退 | `console.log` 会有原因；多数是端口被占或配置 JSON 写坏 |

## 自己编译

装 Go 1.22+，然后：

```bash
./build.sh    # 产出 dist/ 下全部架构
go test ./... # 单测（含与官方 SDK 对拍的签名测试）
```

发布：推一个 `v*` 标签，GitHub Actions 会自动构建五个平台并发布 Release。

## 项目结构

```
lightproxy/
├── main.go            入口：参数、信号、热重载
├── config.go          配置读写与校验
├── proxy.go           反代引擎 + SNI 证书管理
├── security.go        「只允许域名访问」与「安全入口」拦截
├── sniff.go           同端口区分 TLS / 明文（http:// 误连时 307 到 https）
├── fw.go              端口转发：iptables/nftables 下发、回滚、开机持久化
├── tcpfwd.go          IPv6 用户态裸 TCP/UDP 转发（跨协议族映射到内网 IPv4）
├── knock.go           转发端口的敲门放行名单（来源 /64，7 天有效）
├── acme.go            ACME v2 客户端（DNS-01，ES256 手写 JWS）+ 自动续期
├── ddns.go            DDNS 调度与公网 IP 探测
├── aliyun.go          阿里云 DNS 客户端（RPC 签名 v1）
├── admin.go           管理面板 API 与会话
├── logs.go            环形日志（512KB 自动轮转）
├── web/               内嵌前端（单页，无框架）
├── scripts/install.sh 路由器安装脚本（向导式：安装 / 卸载 / 选目录）
└── test/              mock 阿里云 API、echo 后端、WS 测试
```

## 测试覆盖

- 阿里云 RPC 签名与官方 SDK 输出逐字节对拍
- ACME：ES256 签名格式（r||s 64 字节）、RFC 7638 thumbprint、JWS 结构（POST-as-GET 空载荷）、
  以及 **mock CA + mock 阿里云的完整签发端到端**（注册账户 → 下单 → 加 TXT → 触发验证 → finalize → 下载证书，全程由 mock 侧用标准库验签）
- 端口转发：iptables 持久化脚本、nftables 脚本生成、hairpin、停用规则过滤、本机端口放行、冲突端口跳过
- IPv6 裸转发：TCP/UDP 往返、签名不变不重建、停止后端口释放
- 敲门放行：/64 前缀归并（隐私扩展轮换接口 ID 不影响）、过期清除、未启用全放行、转发 TCP 未敲门秒断
- 访问控制：IPv4/IPv6 直连拦截、回环豁免、反代访问面板（X-Forwarded-Host）、泛域名匹配
- 安全入口：路径规范化（拒绝 `?`、`#`、`%`、空格、`//`）、入口前缀剥离、前缀相似不误判（`/entryx`）、
  内网/本机豁免、票据放行与伪造票据拒绝、改入口后旧票据失效
- 同端口协议嗅探：TLS 握手记录走 TLS 侧、明文 `GET` 走跳转侧、只发一个字节也能还原完整请求、关闭监听后不阻塞
- HTTP 跳转：Location 保留原始路径与查询串，公网端口非 443 时带上端口；`http://` 误连 HTTPS 端口回 307 且端口不变；
  「额外 HTTP 监听」与反代端口写成同一个时不再重复监听（`sameListenPort`），防火墙放行也不会重复
- DDNS：泛域名/FQDN 自动拆分（`*.example.com` → 主域名 + `*`）
- 配置校验：端口冲突（TCP/UDP 分开）、目标必须 IPv4、ACME 域名合法性、密钥复用不写回

## License

MIT License © 2026 jxmike

可以自由使用、修改、商用、再分发，唯一要求是保留版权声明和许可证正文（见仓库根目录 `LICENSE`）。

- 本项目为纯 Go 标准库实现，`go.sum` 为空，**不包含任何第三方依赖**，也不含 GPL / AGPL 代码
- 若你把 sing-box / mihomo / xray 等第三方核心的二进制打包进 Release 一起分发，
  需另行遵守它们各自的许可证（分别为 GPL-3.0 / GPL-3.0 / MPL-2.0）；
  本项目的安装脚本是让用户从上游自行下载，不属于再分发。


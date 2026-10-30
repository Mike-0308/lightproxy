# 轻代理 LightProxy

给内存吃紧的路由器用的 **反向代理 + 端口转发 + 阿里云 DDNS + 自动证书**。

- 单文件，静态链接，零依赖：约 6.6MB（armv7）
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
- HTTPS：单证书或证书目录（按 SNI 自动选证书，支持多域名）
- HTTP → HTTPS 自动 301 跳转（可选，外网映射端口非 443 时会带上端口）

**端口转发（内核 DNAT）**
- 面板管规则，写入 iptables（fw3/fw4 都可用）或 nftables，转发由内核完成，不占进程内存
- TCP / UDP / 两者，支持内网回环（hairpin，内网设备用公网 IP 也能访问）
- 规则只写进自家链（`LP_FWD` / `LP_ACL` / `LP_IN` / `LP_MASQ`），不动系统已有规则，失败自动清空回滚，不会把路由器搞断网
- 自动放行：FORWARD 转发与回程连接（精确到目标地址+端口），并把**反代监听端口**写进 INPUT 放行——路由器自带防火墙全开时，也只有这些端口能从外网进来；管理面板端口永远不会被放行
- 自动生成开机脚本并挂到 `/etc/config/firewall` 的 include（uci），重启路由规则不丢
- 需要以 root 运行（iptables 需要 CAP_NET_ADMIN）

**只允许域名访问（安全）**
- 打开后，**外网**用 IP（v4/v6）直连反代端口或面板端口一律 403，只认域名
- **内网（192.168.x / 10.x / 172.16-31.x / fe80:: / fd00::）和本机不受影响**，用 IP 直连照常用——内网没有安全风险
- 面板藏在反代后面也能正常进（自动识别 `X-Forwarded-Host`）
- 与路由器自带的 IPv6 防火墙配合：防火墙挡端口，这一层挡「外网 IP:端口 直接打开」

**配置备份**
- 设置页一键导出全部配置为 JSON 文件（含 AccessKey，注意保管）
- 导入前先校验，不合法的文件不生效；导入即热应用，无需重启，适合迁移到别的设备

**自动证书（ACME DNS-01）**
- 支持 Let's Encrypt（含测试环境）与 ZeroSSL，CA 地址可自定义
- DNS-01 验证走阿里云解析：自动添加/清理 TXT 记录，不占 80 端口、不与反代抢路径、支持泛域名
- AccessKey 留空自动复用 DDNS 的（运行时复用，改 DDNS 密钥这里跟着变）
- 签发后写入证书目录并热加载；后台每小时巡检，剩余有效期低于阈值（默认 30 天）自动续
- 「检查配置」可提前验证 AccessKey 与每个域名能否找到解析，避免签发一半才失败

**DDNS（阿里云）**
- A / AAAA 记录，多条域名；支持泛解析（`*`）与多级前缀
- 「域名」栏可以直接写 `*.example.com` 这样的完整域名，保存时自动拆成主域名 + 主机记录
- 公网 IP 两种获取方式：在线接口查询（默认）/ 读网卡地址（PPPoE 拨号）
- 值没变不写 API，只在变化时新增/更新（对阿里云接口零浪费）
- 「测试 AccessKey」「检测公网 IP」「立即同步」一键排查

**管理面板**（默认 `http://路由器IP:8081/`）
- 概览：运行时长、内存、请求计数，反代/DDNS/端口转发/证书四块状态一屏看完
- 反代规则 / 端口转发 / DDNS / 证书全部可视化编辑，保存即生效
- 配置备份：设置页一键导出全部配置为 JSON（含 AccessKey，注意保管），导入前先校验、不合法不生效，可用来迁移到别的设备
- 内存环形日志（最近 600 条，不占闪存）
- 一键重启、证书热重载

## 一行安装

路由器 SSH 里执行（自动识别架构、从 GitHub Releases 下载、配置自启）：

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/lightproxy/main/scripts/install.sh | sh
```

也可以先下载再装：

```bash
# 上传二进制和安装脚本
scp dist/lightproxy-linux-armv7 scripts/install.sh root@192.168.10.1:/tmp/
# SSH 进去安装（配置已存在时会保留）
ssh root@192.168.10.1 "sh /tmp/install.sh /tmp/lightproxy-linux-armv7"
```

浏览器打开 `http://192.168.10.1:8081/`，密码在安装输出的「管理面板账号」一行。

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

**卸载**（停服务、清掉全部自启挂钩、删除程序与配置目录）：

```bash
# 已把 install.sh 传到路由器的情况
sh /tmp/install.sh --uninstall

# 没传过脚本时，一行远程卸载（OWNER 换成仓库作者）
curl -fsSL https://raw.githubusercontent.com/OWNER/lightproxy/main/scripts/install.sh | sh -s -- --uninstall
```

卸载会先摘掉开机挂钩再停进程（避免 procd 的 respawn 又拉起来），然后删除 `/data/lightproxy`。
如需保留配置，卸载前先在面板「设置 → 配置备份 → 导出配置」下载一份。

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

1. **面板 → 端口转发**：加一条 `443 → 路由器LAN IP:8443` 的规则，「保存并下发」。
   开启本页后，反代监听端口（8443）和 HTTP 跳转端口（80，如果开了跳转）会一并写进 INPUT 放行；
   规则持久化、重启自动恢复。
2. **路由器自带防火墙**（如 IPv6 防火墙）可以放心全开——只放行了上述端口。
3. **面板 → 设置 → 访问控制**：打开「只允许域名访问」，外网拿 IP 扫不到你的服务（内网不受影响）。
   同时建议加一条反代规则把面板藏在域名后面：`panel.example.com → http://127.0.0.1:8081`。
4. 外网用 `https://nas.example.com` 访问；HTTP 会自动 301 到 HTTPS。

也可以用路由器后台自带的端口转发页面，或 SSH 手工命令：

```bash
iptables -t nat -A PREROUTING -i pppoe-wan -p tcp --dport 443 -j DNAT --to-destination 192.168.31.1:8443
iptables -t nat -A PREROUTING -i pppoe-wan -p tcp --dport 80  -j DNAT --to-destination 192.168.31.1:8080
iptables -A INPUT -p tcp -m multiport --dports 8080,8443 -j ACCEPT
```

管理面板 8081 **不要**映射到外网（程序层也不会自动放行它）。

## 配置 DDNS

1. 阿里云控制台 → RAM 访问控制 → 创建子用户，**只授予 `AliyunDNSFullAccess`**，生成 AccessKey
2. 面板 → DDNS → 填 AccessKey ID / Secret → 添加记录（主域名 `example.com`，主机记录 `home` 或 `*`，类型 `A`）
3. 「测试 AccessKey」确认密钥可用 → 「检测公网 IP」确认能拿到地址 → 保存
4. 等一个检测周期，或点「立即同步」

PPPoE 拨号且运营商不给公网 IPv4 时，可加一条 AAAA 记录走 IPv6，IP 获取方式选「读取网卡地址」并填 `pppoe-wan`。

## 配置 HTTPS（手动方式）

1. 阿里云 → 数字证书管理 → 申请免费证书（3 个月有效期，绑你的域名），下载 **nginx 格式**
2. 上传到路由器，例如 `/data/lightproxy/certs/nas.example.com.crt` 和 `.key`
3. 面板 → 设置 → HTTPS：开启，证书目录填 `/data/lightproxy/certs`（或填单张证书路径）；
   勾选「HTTP 自动 301 到 HTTPS」，HTTPS 公网端口填外网实际访问的端口（443 直达就填 443）
4. 保存后重启；以后换证书只需替换文件并在面板点「重载证书」，不用重启

**或者用自动证书（推荐）**：面板 → 证书 → 开启，填邮箱和域名（证书目录与上面一致即可），点「检查配置」确认域名能匹配到阿里云解析，然后「立即签发」。之后到期前会自动续，不用再管。

目录里可以放多张证书，按访问的域名（SNI）自动匹配；没匹配到且没配默认证书时会握手失败（这是特性，防止回源错证书）。

## 配置端口转发

面板 → 端口转发 → 开启 → 添加规则（如 `NAS 管理页 / TCP / 5000 → 192.168.10.10:5000`）→ 「保存并下发」。

- 「生效状态」卡片会显示后端（iptables/nftables）、生效条数、放行端口、开机持久化结果
- 下发失败会自动回滚并在面板显示原因（最常见是没用 root 运行）
- 「清空内核规则」只清本工具自己的链，不影响路由器原有转发

## 配置字段速查

| 字段 | 说明 |
|---|---|
| `listen` | 反代监听，默认 `:18080`（避开 8080，防止占用路由器管理后台端口） |
| `admin.listen` / `admin.pass` | 面板地址与密码；`pass` 留空则免登录（仅限内网） |
| `tls.redirect` | HTTP 自动 301 到 HTTPS（仅域名访问跳转，IP 直连不跳转） |
| `tls.httpListen` | HTTP 跳转监听地址，勾选跳转后留空默认 `:80` |
| `tls.publicPort` | 外网访问的 HTTPS 端口（非 443 时跳转会带上），默认 443 |
| `security.requireDomain` | 外网只允许域名访问（IP 直连 403）；内网与本机始终放行 |
| `security.allowLoopback` | 回环豁免，允许 127.0.0.1 / ::1 访问面板（默认开） |
| `security.extraHosts` | 额外放行的域名（逗号分隔） |
| `proxy[].hosts` | 域名列表，支持 `*.example.com`、`*` |
| `proxy[].path` | 路径前缀，`/` 或 `/api`；转发给上游时会剥离 |
| `proxy[].target` | 上游地址，如 `http://192.168.31.10:5000` |
| `proxy[].preserveHost` | 透传浏览器原始 Host（反代路由器后台/NAS 需要勾） |
| `proxy[].headers` | 追加请求头，支持 `{client}` `{host}` `{scheme}` 变量 |
| `tls.certDir` | 证书目录，`<域名>.crt` + `<域名>.key`，按 SNI 匹配 |
| `acme.enable/domains/email` | 自动证书：开启、域名列表（支持 `*.example.com`）、联系邮箱 |
| `acme.ca` | `letsencrypt`（默认）/ `letsencrypt-staging` / `zerossl` / 自定义 directory URL |
| `acme.certDir` | 签发结果写入目录，留空继承 `tls.certDir` |
| `acme.renewDays` | 剩余多少天进入续期，默认 30（7~60） |
| `acme.accessKeyId/Secret` | 留空自动复用 `ddns` 的密钥（仅运行时，不写回配置） |
| `forward.enable` | 端口转发总开关；关闭时启动会清理自家链 |
| `forward.backend` | `auto`（默认）/ `iptables` / `nftables` / `off` |
| `forward.hairpin` | 内网回环（MASQUERADE），内网设备用公网 IP 访问时需要 |
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
| 面板打不开 | `netstat -lntp \| grep 8081` 看端口；`/data/lightproxy/ctl status` 看进程；`console.log` 看报错 |
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
├── security.go        「只允许域名访问」拦截
├── fw.go              端口转发：iptables/nftables 下发、回滚、开机持久化
├── acme.go            ACME v2 客户端（DNS-01，ES256 手写 JWS）+ 自动续期
├── ddns.go            DDNS 调度与公网 IP 探测
├── aliyun.go          阿里云 DNS 客户端（RPC 签名 v1）
├── admin.go           管理面板 API 与会话
├── logs.go            环形日志（512KB 自动轮转）
├── web/               内嵌前端（单页，无框架）
├── scripts/install.sh 路由器安装/卸载脚本（支持一行安装）
└── test/              mock 阿里云 API、echo 后端、WS 测试
```

## 测试覆盖

- 阿里云 RPC 签名与官方 SDK 输出逐字节对拍
- ACME：ES256 签名格式（r||s 64 字节）、RFC 7638 thumbprint、JWS 结构（POST-as-GET 空载荷）、
  以及 **mock CA + mock 阿里云的完整签发端到端**（注册账户 → 下单 → 加 TXT → 触发验证 → finalize → 下载证书，全程由 mock 侧用标准库验签）
- 端口转发：iptables 持久化脚本、nftables 脚本生成、hairpin、停用规则过滤、本机端口放行
- 访问控制：IPv4/IPv6 直连拦截、回环豁免、反代访问面板（X-Forwarded-Host）、泛域名匹配
- HTTP 跳转：Location 保留原始路径与查询串，公网端口非 443 时带上端口
- DDNS：泛域名/FQDN 自动拆分（`*.example.com` → 主域名 + `*`）
- 配置校验：端口冲突（TCP/UDP 分开）、目标必须 IPv4、ACME 域名合法性、密钥复用不写回

## License

MIT

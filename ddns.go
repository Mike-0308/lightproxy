package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// RecordState 是单条解析记录在面板上展示的运行状态。
type RecordState struct {
	Key       string    `json:"key"`
	Domain    string    `json:"domain"`
	RR        string    `json:"rr"`
	Type      string    `json:"type"`
	Current   string    `json:"current"`
	Desired   string    `json:"desired"`
	State     string    `json:"state"`
	Message   string    `json:"message"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type DDNSStatus struct {
	Enabled    bool          `json:"enabled"`
	Provider   string        `json:"provider"`
	Interval   int           `json:"interval"`
	IPMode     string        `json:"ipMode"`
	Interface  string        `json:"interface"`
	PublicIPv4 string        `json:"publicIpv4"`
	PublicIPv6 string        `json:"publicIpv6"`
	LastRun    time.Time     `json:"lastRun"`
	NextRun    time.Time     `json:"nextRun"`
	LastError  string        `json:"lastError"`
	Records    []RecordState `json:"records"`
}

type DDNSManager struct {
	cfg  DDNSConfig
	logs *LogBuffer

	runMu sync.Mutex

	mu      sync.RWMutex
	states  map[string]*RecordState
	cache   map[string]string // key -> RecordId
	lastRun time.Time
	nextRun time.Time
	lastErr string
	ipv4    string
	ipv6    string

	stopOnce sync.Once
	stop     chan struct{}
	wake     chan struct{}
	done     chan struct{}

	// 账号下的域名列表缓存，用于把用户填的 FQDN 拆成 (zone, RR)
	zonesMu sync.Mutex
	zones   []string
	zonesAt time.Time
}

func NewDDNSManager(cfg DDNSConfig, logs *LogBuffer) *DDNSManager {
	return &DDNSManager{
		cfg:    cfg,
		logs:   logs,
		states: map[string]*RecordState{},
		cache:  map[string]string{},
		stop:   make(chan struct{}),
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

func recKey(r DNSRecord) string {
	return r.RR + "." + r.Domain + "|" + r.Type
}

func (m *DDNSManager) Start() {
	if !m.cfg.Enable {
		m.logs.Infof("DDNS 未启用")
		return
	}
	if err := m.seedStates(); err != nil {
		m.logs.Errorf("DDNS: %v", err)
		return
	}
	// 启动后延迟几秒再跑，避免和网络拨号抢时间
	go func() {
		select {
		case <-time.After(5 * time.Second):
		case <-m.stop:
			return
		}
		m.run()
		m.loop()
	}()
	m.logs.Infof("DDNS 已启动：%s，%d 条记录，间隔 %d 秒", m.cfg.Provider, len(m.cfg.Records), m.cfg.Interval)
}

func (m *DDNSManager) seedStates() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.cfg.Records {
		if r.Disable {
			continue
		}
		k := recKey(r)
		if _, ok := m.states[k]; !ok {
			m.states[k] = &RecordState{
				Key: k, Domain: r.Domain, RR: r.RR, Type: r.Type,
				State: "pending", Message: "等待首次检测",
			}
		}
	}
	return nil
}

func (m *DDNSManager) loop() {
	defer close(m.done)
	t := time.NewTicker(time.Duration(m.cfg.Interval) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-m.wake:
			m.run()
		case <-t.C:
			m.run()
		}
	}
}

func (m *DDNSManager) Stop() {
	m.stopOnce.Do(func() { close(m.stop) })
}

func (m *DDNSManager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// RunNow 供管理面板「立即检测」使用，同步执行并返回是否全部成功。
func (m *DDNSManager) RunNow() error {
	if !m.cfg.Enable {
		return errors.New("DDNS 未启用")
	}
	return m.run()
}

func (m *DDNSManager) run() error {
	if !m.cfg.Enable || len(m.cfg.Records) == 0 {
		return nil
	}
	if !m.runMu.TryLock() {
		return nil
	}
	defer m.runMu.Unlock()

	need4, need6 := false, false
	for _, r := range m.cfg.Records {
		if r.Disable {
			continue
		}
		if r.Type == "AAAA" {
			need6 = true
		} else {
			need4 = true
		}
	}

	var v4, v6 string
	var err4, err6 error
	if need4 {
		v4, err4 = m.detect(4)
	}
	if need6 {
		v6, err6 = m.detect(6)
	}
	m.mu.Lock()
	m.ipv4, m.ipv6 = v4, v6
	m.mu.Unlock()

	client := newAliyunClient(m.cfg.AccessKey, m.cfg.SecretKey, m.cfg.Insecure)
	zones := m.resolveZones(client)
	var errs []string

	for _, r := range m.cfg.Records {
		if r.Disable {
			continue
		}
		k := recKey(r)

		// 允许「域名」栏直接写 *.example.com / home.example.com，这里统一拆成 zone + RR。
		zone, rr := resolveRecord(r, zones)
		if zone != r.Domain || rr != r.RR {
			m.setState(k, func(s *RecordState) { s.Domain, s.RR = zone, rr })
		}

		desired := v4
		var derr error = err4
		if r.Type == "AAAA" {
			desired, derr = v6, err6
		}
		if derr != nil || desired == "" {
			msg := "未检测到可用的公网 IP"
			if derr != nil {
				msg = derr.Error()
			}
			m.setState(k, func(s *RecordState) {
				s.Desired = ""
				s.State = "error"
				s.Message = msg
				s.UpdatedAt = time.Now()
			})
			errs = append(errs, fmt.Sprintf("%s: %s", k, msg))
			continue
		}

		m.setState(k, func(s *RecordState) { s.Desired = desired })

		if err := m.syncRecord(client, r, zone, rr, desired); err != nil {
			m.setState(k, func(s *RecordState) {
				s.State = "error"
				s.Message = err.Error()
				s.UpdatedAt = time.Now()
			})
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
			m.logs.Errorf("DDNS %s 更新失败: %v", k, err)
		}
	}

	now := time.Now()
	m.mu.Lock()
	m.lastRun = now
	m.nextRun = now.Add(time.Duration(m.cfg.Interval) * time.Second)
	if len(errs) > 0 {
		m.lastErr = strings.Join(errs, "; ")
	} else {
		m.lastErr = ""
	}
	m.mu.Unlock()

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// resolveZones 拉取账号下的域名列表并缓存 10 分钟；失败时沿用旧缓存或返回 nil。
func (m *DDNSManager) resolveZones(c *aliyunClient) []string {
	m.zonesMu.Lock()
	defer m.zonesMu.Unlock()
	if len(m.zones) > 0 && time.Since(m.zonesAt) < 10*time.Minute {
		return m.zones
	}
	list, err := c.ListDomains()
	if err != nil {
		if len(m.zones) > 0 {
			return m.zones
		}
		m.logs.Errorf("DDNS: 读取域名列表失败，按填写值直接提交（%v）", err)
		return nil
	}
	m.zones, m.zonesAt = list, time.Now()
	return list
}

// resolveRecord 把用户填写的「域名 + 主机记录」还原成阿里云要的 (zone, RR)。
// 支持在「域名」栏直接写 FQDN：*.example.com → (example.com, *)、home.example.com → (example.com, home)。
// 账号里找不到匹配域名时，保持用户填写值不变（交给接口报错，错误信息里再解释）。
func resolveRecord(r DNSRecord, zones []string) (zone, rr string) {
	fqdn := r.Domain
	if r.RR != "" && r.RR != "@" {
		fqdn = r.RR + "." + r.Domain
	}
	if z, x, ok := pickZone(fqdn, zones); ok {
		return z, x
	}
	return r.Domain, r.RR
}

// friendlyAPIError 把阿里云常见的几个错误码翻成人话。
func friendlyAPIError(err error, zone string) error {
	ae, ok := err.(*APIError)
	if !ok {
		return err
	}
	switch ae.Code {
	case "InvalidDomainName.NoExist":
		return fmt.Errorf("阿里云账号里没有域名 %s。请确认「域名」栏填的是主域名（如 example.com），"+
			"泛解析把 * 填在「主机记录」栏（或直接在域名栏写 *.example.com）", zone)
	case "InvalidAccessKeyId.NotFound", "InvalidAccessKeyId":
		return fmt.Errorf("AccessKey 无效或已被禁用（%s）", ae.Code)
	case "SignatureDoesNotMatch":
		return fmt.Errorf("签名校验失败，多半是路由器时间不准，先确认 NTP 同步（%s）", ae.Code)
	}
	return err
}

// syncRecord 对比解析记录，必要时新增/更新。zone/rr 是已解析好的真实域名与主机记录。
func (m *DDNSManager) syncRecord(c *aliyunClient, r DNSRecord, zone, rr, desired string) error {
	sub := zone
	if rr != "@" && rr != "" {
		sub = rr + "." + zone
	}

	existing, err := c.DescribeSubDomain(sub, r.Type)
	if err != nil {
		return fmt.Errorf("查询解析记录失败: %w", friendlyAPIError(err, zone))
	}

	var hit *aliyunRecord
	for i := range existing {
		e := &existing[i]
		if e.Type != r.Type {
			continue
		}
		if strings.EqualFold(e.RR, rr) || (rr == "@" && (e.RR == "@" || e.RR == "")) {
			hit = e
			break
		}
	}

	k := recKey(r)
	if hit == nil {
		ttl := r.TTL
		if ttl <= 0 {
			ttl = m.cfg.TTL
		}
		if _, err := c.AddRecord(zone, rr, r.Type, desired, ttl); err != nil {
			if ae, ok := err.(*APIError); ok && ae.Code == "DomainRecordDuplicate" {
				// 并发或缓存过期导致重复，回查一次再更新
				if recs, e2 := c.DescribeSubDomain(sub, r.Type); e2 == nil {
					for i := range recs {
						if recs[i].Type == r.Type && strings.EqualFold(recs[i].RR, rr) {
							hit = &recs[i]
							break
						}
					}
				}
				if hit == nil {
					return err
				}
			} else {
				return fmt.Errorf("新增解析记录失败: %w", friendlyAPIError(err, zone))
			}
		} else {
			m.mu.Lock()
			m.cache[k] = ""
			m.mu.Unlock()
			m.setState(k, func(s *RecordState) {
				s.Current = desired
				s.State = "added"
				s.Message = "已新增解析记录"
				s.UpdatedAt = time.Now()
			})
			m.logs.Infof("DDNS %s.%s %s 已新增 -> %s", rr, zone, r.Type, desired)
			return nil
		}
	}

	if hit.Value == desired {
		m.mu.Lock()
		m.cache[k] = hit.RecordID
		m.mu.Unlock()
		m.setState(k, func(s *RecordState) {
			s.Current = hit.Value
			s.State = "ok"
			s.Message = "解析已是最新"
			s.UpdatedAt = time.Now()
		})
		return nil
	}

	ttl := hit.TTL
	if ttl <= 0 {
		ttl = m.cfg.TTL
	}
	if err := c.UpdateRecord(hit.RecordID, hit.RR, hit.Type, desired, ttl); err != nil {
		return fmt.Errorf("更新解析记录失败: %w", friendlyAPIError(err, zone))
	}
	m.mu.Lock()
	m.cache[k] = hit.RecordID
	m.mu.Unlock()
	old := hit.Value
	m.setState(k, func(s *RecordState) {
		s.Current = desired
		s.State = "updated"
		s.Message = "解析已更新"
		s.UpdatedAt = time.Now()
	})
	m.logs.Infof("DDNS %s.%s %s 已更新: %s -> %s", rr, zone, r.Type, old, desired)
	return nil
}

func (m *DDNSManager) setState(key string, fn func(*RecordState)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[key]
	if !ok {
		s = &RecordState{Key: key}
		m.states[key] = s
	}
	fn(s)
}

func (m *DDNSManager) Snapshot() DDNSStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := DDNSStatus{
		Enabled:    m.cfg.Enable,
		Provider:   m.cfg.Provider,
		Interval:   m.cfg.Interval,
		IPMode:     m.cfg.IPMode,
		Interface:  m.cfg.Interface,
		PublicIPv4: m.ipv4,
		PublicIPv6: m.ipv6,
		LastRun:    m.lastRun,
		NextRun:    m.nextRun,
		LastError:  m.lastErr,
		Records:    []RecordState{},
	}
	keys := make([]string, 0, len(m.states))
	for k := range m.states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Records = append(out.Records, *m.states[k])
	}
	return out
}

func (m *DDNSManager) TestCredentials() (int, error) {
	if m.cfg.AccessKey == "" || m.cfg.SecretKey == "" {
		return 0, errors.New("未填写 AccessKey")
	}
	c := newAliyunClient(m.cfg.AccessKey, m.cfg.SecretKey, m.cfg.Insecure)
	return c.TestCredentials()
}

// ---------------- 公网 IP 探测 ----------------

var ipTokenRe = regexp.MustCompile(`[0-9a-fA-F:.]+`)

func (m *DDNSManager) detect(family int) (string, error) {
	if m.cfg.IPMode == "interface" {
		return detectFromInterface(m.cfg.Interface, family)
	}
	sources := m.cfg.IPSources
	if len(sources) == 0 {
		sources = DefaultConfig().DDNS.IPSources
	}
	if family == 6 {
		v6 := []string{"https://api6.ipify.org", "https://v6.ident.me"}
		sources = append(v6, sources...)
	}

	var lastErr error
	for _, src := range sources {
		ip, err := fetchIP(src, family)
		if err != nil {
			lastErr = err
			continue
		}
		return ip, nil
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的 IP 查询源")
	}
	return "", fmt.Errorf("公网 IP 查询失败: %w", lastErr)
}

func fetchIP(src string, family int) (string, error) {
	cli := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "curl/8.0 lightproxy/"+version)
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	for _, tok := range ipTokenRe.FindAllString(string(body), -1) {
		ip := net.ParseIP(strings.Trim(tok, ".:"))
		if ip == nil {
			continue
		}
		if family == 4 {
			if v4 := ip.To4(); v4 != nil && isPublic(v4) {
				return v4.String(), nil
			}
			continue
		}
		if ip.To4() == nil && isPublic(ip) {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("%s 未返回公网 IPv%d", src, family)
}

func isPublic(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip.To4() == nil && len(ip) == 16 && ip[0]&0xfe == 0xfc { // ULA fc00::/7
		return false
	}
	return true
}

func detectFromInterface(name string, family int) (string, error) {
	ifaces := []net.Interface{}
	if name != "" {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return "", fmt.Errorf("找不到网卡 %s: %w", name, err)
		}
		ifaces = append(ifaces, *ifi)
	} else {
		all, err := net.Interfaces()
		if err != nil {
			return "", err
		}
		for _, i := range all {
			if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
				continue
			}
			ifaces = append(ifaces, i)
		}
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || !isPublic(ip) {
				continue
			}
			if family == 4 {
				if v4 := ip.To4(); v4 != nil {
					return v4.String(), nil
				}
			} else if ip.To4() == nil {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("网卡 %s 上没有公网 IPv%d 地址", orAll(name), family)
}

func orAll(s string) string {
	if s == "" {
		return "(全部)"
	}
	return s
}

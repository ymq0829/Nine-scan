// scanner/vuln.go
package scanner

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"example.com/project/controller"
)

// Vulnerability 漏洞信息
type Vulnerability struct {
	Port           int    `json:"port"`
	Service        string `json:"service"`
	CVE            string `json:"cve"`
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	AffectedFrom   string `json:"affected_from,omitempty"`   // 受影响的起始版本
	AffectedTo     string `json:"affected_to,omitempty"`     // 受影响的结束版本
	FixedVersion   string `json:"fixed_version,omitempty"`   // 修复版本
	Description    string `json:"description,omitempty"`     // 漏洞描述
	CheckMethod    string `json:"check_method"`              // 检测方法：version/feature/exploit
	DetectionRegex string `json:"detection_regex,omitempty"` // 特征检测正则表达式
	ExploitPayload string `json:"exploit_payload,omitempty"` // 漏洞利用载荷（可选）
}

// VulnScanner 漏洞扫描器
type VulnScanner struct {
	targets      map[string][]int           // key: 主机IP, value: 开放端口列表
	services     map[string]map[int]string  // key: 主机IP, value: map[端口]服务名
	timeout      time.Duration              // 连接超时时间
	logger       *controller.Logger         // 日志记录器
	vulnDatabase map[string][]Vulnerability // 漏洞数据库（扩展版）
}

// NewVulnScanner 初始化漏洞扫描器
func NewVulnScanner(openPorts map[string][]int, services map[string]map[int]string, logger *controller.Logger) *VulnScanner {
	scanner := &VulnScanner{
		targets:      openPorts,
		services:     services,
		timeout:      5 * time.Second,
		logger:       logger,
		vulnDatabase: make(map[string][]Vulnerability),
	}

	// 尝试从文件加载漏洞数据库
	if err := scanner.LoadVulnerabilityDatabase("vulnerabilities.json"); err != nil {
		// 如果加载失败，使用内置漏洞数据库
		scanner.logger.Logf("加载漏洞数据库失败: %v, 使用内置数据库", err)
		scanner.initializeDefaultVulnDatabase()
	} else {
		scanner.logger.Log("成功加载漏洞数据库")
	}

	return scanner
}

// 初始化默认漏洞数据库
func (s *VulnScanner) initializeDefaultVulnDatabase() {
	vulnDB := make(map[string][]Vulnerability)

	// 添加SSH相关漏洞 - 匹配多种服务名称
	sshVulns := []Vulnerability{
		{
			Port:           22,
			Service:        "SSH",
			CVE:            "CVE-2018-15473",
			Name:           "OpenSSH 用户枚举漏洞",
			Severity:       "Medium",
			AffectedFrom:   "7.5",
			AffectedTo:     "7.7",
			FixedVersion:   "7.8",
			Description:    "OpenSSH 7.5到7.7版本中存在用户枚举漏洞，攻击者可以通过特定请求判断用户是否存在。",
			CheckMethod:    "version",
			DetectionRegex: "",
			ExploitPayload: "",
		},
		{
			Port:           22,
			Service:        "SSH",
			CVE:            "CVE-2020-14145",
			Name:           "OpenSSH 命令注入漏洞",
			Severity:       "High",
			AffectedFrom:   "7.4",
			AffectedTo:     "8.3",
			FixedVersion:   "8.4",
			Description:    "OpenSSH 7.4到8.3版本中存在命令注入漏洞，攻击者可以通过特定构造的参数执行任意命令。",
			CheckMethod:    "version",
			DetectionRegex: "",
			ExploitPayload: "",
		},
	}

	// 添加多种服务名称映射
	vulnDB["SSH"] = sshVulns
	vulnDB["SSH (Secure Shell)"] = sshVulns
	vulnDB["OpenSSH"] = sshVulns
	vulnDB["Dropbear SSH"] = sshVulns
	vulnDB["PORT_22"] = sshVulns

	// 添加HTTP相关漏洞
	httpVulns := []Vulnerability{
		{
			Port:           80,
			Service:        "HTTP",
			CVE:            "CVE-2019-11043",
			Name:           "PHP-FPM 远程代码执行漏洞",
			Severity:       "Critical",
			AffectedFrom:   "7.1.0",
			AffectedTo:     "7.3.10",
			FixedVersion:   "7.3.11",
			Description:    "PHP-FPM在处理PATH_INFO时存在远程代码执行漏洞，攻击者可以构造特殊请求执行任意代码。",
			CheckMethod:    "feature",
			DetectionRegex: "PHP/[0-9.]+-fpm",
			ExploitPayload: "",
		},
		{
			Port:           80,
			Service:        "HTTP",
			CVE:            "CVE-2021-41773",
			Name:           "Apache HTTP Server 路径遍历与文件读取漏洞",
			Severity:       "High",
			AffectedFrom:   "2.4.49",
			AffectedTo:     "2.4.50",
			FixedVersion:   "2.4.51",
			Description:    "Apache HTTP Server 2.4.49和2.4.50版本中存在路径遍历漏洞，攻击者可以读取Web根目录外的文件。",
			CheckMethod:    "feature",
			DetectionRegex: "Apache/2.4\\.(49|50)",
			ExploitPayload: "",
		},
	}

	// 添加多种服务名称映射
	vulnDB["HTTP"] = httpVulns
	vulnDB["HTTP Web Service"] = httpVulns
	vulnDB["HTTP/HTTPS Web Service"] = httpVulns
	vulnDB["Apache HTTP Server"] = httpVulns
	vulnDB["Nginx HTTP Server"] = httpVulns
	vulnDB["Microsoft IIS"] = httpVulns
	vulnDB["Web Server"] = httpVulns
	vulnDB["PORT_80"] = httpVulns
	vulnDB["PORT_8080"] = httpVulns
	vulnDB["PORT_8081"] = httpVulns
	vulnDB["PORT_443"] = httpVulns

	// 添加SMB相关漏洞（包含用户提到的漏洞）
	smbVulns := []Vulnerability{
		{
			Port:           445,
			Service:        "SMB",
			CVE:            "CVE-2017-0144",
			Name:           "EternalBlue SMB 远程代码执行漏洞",
			Severity:       "Critical",
			AffectedFrom:   "6.0",
			AffectedTo:     "10.0",
			FixedVersion:   "10.0.14393.1198",
			Description:    "Windows SMBv1服务器中存在远程代码执行漏洞，攻击者可以通过发送特制的数据包执行任意代码。",
			CheckMethod:    "feature",
			DetectionRegex: "SMBv1|Windows.*SMB",
			ExploitPayload: "",
		},
		{
			Port:           445,
			Service:        "SMB",
			CVE:            "CVE-2020-0796",
			Name:           "SMBGhost SMBv3 远程代码执行漏洞",
			Severity:       "Critical",
			AffectedFrom:   "10.0.18362",
			AffectedTo:     "10.0.18363",
			FixedVersion:   "10.0.18363.1059",
			Description:    "Windows SMBv3客户端/服务器中存在远程代码执行漏洞，攻击者可以通过发送特制的压缩数据包执行任意代码。",
			CheckMethod:    "feature",
			DetectionRegex: "SMBv3.*compression|Windows.*10\\.0\\.(18362|18363)",
			ExploitPayload: "",
		},
		{
			Port:           445,
			Service:        "SMB",
			CVE:            "CVE-2020-1350",
			Name:           "Windows DNS服务器远程代码执行漏洞( SIGRed )",
			Severity:       "Critical",
			AffectedFrom:   "6.1",
			AffectedTo:     "10.0",
			FixedVersion:   "2020-07-14安全更新",
			Description:    "Windows DNS服务器在处理特定请求时存在远程代码执行漏洞，攻击者可以通过发送特制的数据包执行任意代码。",
			CheckMethod:    "feature",
			DetectionRegex: "SMB|Microsoft Windows",
			ExploitPayload: "",
		},
	}

	vulnDB["SMB"] = smbVulns
	vulnDB["SMB/CIFS"] = smbVulns
	vulnDB["File Sharing"] = smbVulns
	vulnDB["SMB (Unknown version)"] = smbVulns
	vulnDB["PORT_445"] = smbVulns

	// 添加DCE/RPC相关漏洞（端口135）
	dceRpcVulns := []Vulnerability{
		{
			Port:           135,
			Service:        "DCE/RPC",
			CVE:            "CVE-2003-0352",
			Name:           "DCOM RPC 缓冲区溢出漏洞",
			Severity:       "Critical",
			AffectedFrom:   "5.0",
			AffectedTo:     "2003",
			FixedVersion:   "MS03-026",
			Description:    "Windows DCOM RPC服务存在缓冲区溢出漏洞，攻击者可以远程执行代码。",
			CheckMethod:    "feature",
			DetectionRegex: "RPC|DCOM|Microsoft Windows",
			ExploitPayload: "",
		},
		{
			Port:           135,
			Service:        "DCE/RPC",
			CVE:            "CVE-2019-0708",
			Name:           "BlueKeep 远程桌面服务漏洞",
			Severity:       "Critical",
			AffectedFrom:   "7.0",
			AffectedTo:     "2008 R2",
			FixedVersion:   "MS19-07",
			Description:    "Windows远程桌面服务存在远程代码执行漏洞，允许未经身份验证的攻击者执行任意代码。",
			CheckMethod:    "feature",
			DetectionRegex: "RPC|DCOM|Microsoft Windows",
			ExploitPayload: "",
		},
	}

	vulnDB["DCE/RPC"] = dceRpcVulns
	vulnDB["RPC"] = dceRpcVulns
	vulnDB["DCOM"] = dceRpcVulns
	vulnDB["PORT_135"] = dceRpcVulns

	// 添加FTP相关漏洞
	ftpVulns := []Vulnerability{
		{
			Port:           21,
			Service:        "FTP",
			CVE:            "CVE-2011-2523",
			Name:           "ProFTPD 远程代码执行漏洞",
			Severity:       "Critical",
			AffectedFrom:   "1.3.3c",
			AffectedTo:     "1.3.3g",
			FixedVersion:   "1.3.4",
			Description:    "ProFTPD在处理TELNET IAC序列时存在缓冲区溢出漏洞，允许攻击者执行任意代码。",
			CheckMethod:    "feature",
			DetectionRegex: "ProFTPD/[0-9.]+",
			ExploitPayload: "",
		},
	}

	vulnDB["FTP"] = ftpVulns
	vulnDB["PORT_21"] = ftpVulns

	// 添加Telnet相关漏洞
	telnetVulns := []Vulnerability{
		{
			Port:           23,
			Service:        "Telnet",
			CVE:            "CVE-2012-0897",
			Name:           "Linux PAM 认证绕过漏洞",
			Severity:       "High",
			AffectedFrom:   "1.1.2",
			AffectedTo:     "1.1.3",
			FixedVersion:   "1.1.4",
			Description:    "Linux PAM模块存在认证绕过漏洞，允许攻击者无需密码访问系统。",
			CheckMethod:    "feature",
			DetectionRegex: "telnetd|Telnet",
			ExploitPayload: "",
		},
	}

	vulnDB["Telnet"] = telnetVulns
	vulnDB["PORT_23"] = telnetVulns

	// 添加MySQL相关漏洞
	mysqlVulns := []Vulnerability{
		{
			Port:           3306,
			Service:        "MySQL",
			CVE:            "CVE-2016-6662",
			Name:           "MySQL 远程代码执行漏洞",
			Severity:       "Critical",
			AffectedFrom:   "5.5.0",
			AffectedTo:     "5.7.15",
			FixedVersion:   "5.7.16",
			Description:    "MySQL服务器存在远程代码执行漏洞，允许攻击者执行任意代码。",
			CheckMethod:    "feature",
			DetectionRegex: "MySQL.*([0-9.]+)",
			ExploitPayload: "",
		},
	}

	vulnDB["MySQL"] = mysqlVulns
	vulnDB["PORT_3306"] = mysqlVulns

	// 添加PostgreSQL相关漏洞
	postgresVulns := []Vulnerability{
		{
			Port:           5432,
			Service:        "PostgreSQL",
			CVE:            "CVE-2019-9193",
			Name:           "PostgreSQL 身份验证绕过漏洞",
			Severity:       "High",
			AffectedFrom:   "9.3",
			AffectedTo:     "11.2",
			FixedVersion:   "11.3",
			Description:    "PostgreSQL存在身份验证绕过漏洞，允许攻击者以超级用户身份访问数据库。",
			CheckMethod:    "feature",
			DetectionRegex: "PostgreSQL.*([0-9.]+)",
			ExploitPayload: "",
		},
	}

	vulnDB["PostgreSQL"] = postgresVulns
	vulnDB["PORT_5432"] = postgresVulns

	// 添加Redis相关漏洞
	redisVulns := []Vulnerability{
		{
			Port:           6379,
			Service:        "Redis",
			CVE:            "CVE-2015-4335",
			Name:           "Redis 未授权访问漏洞",
			Severity:       "High",
			AffectedFrom:   "2.8",
			AffectedTo:     "3.0.5",
			FixedVersion:   "3.0.6",
			Description:    "Redis默认配置允许未授权访问，攻击者可以远程执行命令。",
			CheckMethod:    "feature",
			DetectionRegex: "Redis.*([0-9.]+)",
			ExploitPayload: "",
		},
	}

	vulnDB["Redis"] = redisVulns
	vulnDB["PORT_6379"] = redisVulns

	// 添加VMware相关漏洞
	vmwareVulns := []Vulnerability{
		{
			Port:           902,
			Service:        "VMware",
			CVE:            "CVE-2020-3992",
			Name:           "VMware ESXi 认证绕过漏洞",
			Severity:       "Critical",
			AffectedFrom:   "6.5",
			AffectedTo:     "7.0",
			FixedVersion:   "6.5 U3j, 6.7 U3i, 7.0 U1c",
			Description:    "VMware ESXi、Workstation和Fusion中的OpenSLP服务存在认证绕过漏洞，允许攻击者远程执行代码。",
			CheckMethod:    "version",
			DetectionRegex: "VMware Authentication Daemon Version",
			ExploitPayload: "",
		},
		{
			Port:           902,
			Service:        "VMware",
			CVE:            "CVE-2021-21974",
			Name:           "VMware vCenter Server 命令注入漏洞",
			Severity:       "Critical",
			AffectedFrom:   "6.7",
			AffectedTo:     "7.0",
			FixedVersion:   "6.7 U3o, 7.0 U2c",
			Description:    "VMware vCenter Server中的Analytics服务存在命令注入漏洞，允许攻击者执行任意命令。",
			CheckMethod:    "feature",
			DetectionRegex: "VMware.*Daemon",
			ExploitPayload: "",
		},
		{
			Port:           902,
			Service:        "VMware",
			CVE:            "CVE-2019-5534",
			Name:           "VMware Authentication Daemon 信息泄露漏洞",
			Severity:       "High",
			AffectedFrom:   "1.0",
			AffectedTo:     "1.10",
			FixedVersion:   "1.11",
			Description:    "VMware Authentication Daemon (vmware-authd)中存在信息泄露漏洞，允许攻击者获取敏感信息。",
			CheckMethod:    "version",
			DetectionRegex: "VMware Authentication Daemon Version",
			ExploitPayload: "",
		},
		{
			Port:           912,
			Service:        "VMware",
			CVE:            "CVE-2019-5534",
			Name:           "VMware Authentication Daemon 信息泄露漏洞",
			Severity:       "High",
			AffectedFrom:   "1.0",
			AffectedTo:     "1.10",
			FixedVersion:   "1.11",
			Description:    "VMware Authentication Daemon (vmware-authd)中存在信息泄露漏洞，允许攻击者获取敏感信息。",
			CheckMethod:    "version",
			DetectionRegex: "VMware Authentication Daemon Version",
			ExploitPayload: "",
		},
		{
			Port:           902,
			Service:        "VMware",
			CVE:            "CVE-2022-22954",
			Name:           "VMware ESXi OpenSLP 信息泄露漏洞",
			Severity:       "Medium",
			AffectedFrom:   "1.0",
			AffectedTo:     "7.0",
			FixedVersion:   "ESXi 7.0 Update 3c",
			Description:    "VMware ESXi中的OpenSLP服务存在信息泄露漏洞，允许攻击者获取网络信息。",
			CheckMethod:    "feature",
			DetectionRegex: "VMware",
			ExploitPayload: "",
		},
	}

	vulnDB["VMware"] = vmwareVulns
	vulnDB["VMware Authentication Daemon"] = vmwareVulns
	vulnDB["Unknown"] = vmwareVulns // 添加Unknown服务映射，提高匹配率
	vulnDB["PORT_902"] = vmwareVulns
	vulnDB["PORT_912"] = vmwareVulns

	s.vulnDatabase = vulnDB
}

// LoadVulnerabilityDatabase 从JSON文件加载漏洞数据库
func (s *VulnScanner) LoadVulnerabilityDatabase(dbPath string) error {
	file, err := os.Open(dbPath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(&s.vulnDatabase)
}

// compareVersions 比较两个版本字符串
// 返回值：-1表示v1 < v2，0表示v1 == v2，1表示v1 > v2
func compareVersions(v1, v2 string) int {
	// 清理版本字符串，只保留数字和点
	cleanVersion := func(v string) string {
		regex := regexp.MustCompile(`[^0-9.]`)
		return regex.ReplaceAllString(v, "")
	}

	v1 = cleanVersion(v1)
	v2 = cleanVersion(v2)

	// 如果任一版本为空，无法比较
	if v1 == "" || v2 == "" {
		return 0
	}

	// 分割版本号为数字部分
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// 比较每个数字部分
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int
		var err1, err2 error

		if i < len(parts1) {
			num1, err1 = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			num2, err2 = strconv.Atoi(parts2[i])
		}

		// 如果解析失败，认为该部分版本号为0
		if err1 != nil {
			num1 = 0
		}
		if err2 != nil {
			num2 = 0
		}

		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}

	return 0
}

// IsAffected 判断指定版本是否受此漏洞影响
func (v *Vulnerability) IsAffected(version string) bool {
	if version == "" {
		// 如果没有版本信息，对于版本检测的漏洞也返回true以提高检测率
		return true
	}

	// 检查是否在受影响版本范围内
	if v.AffectedFrom != "" && compareVersions(version, v.AffectedFrom) < 0 {
		return false // 版本早于受影响起始版本
	}

	if v.AffectedTo != "" && compareVersions(version, v.AffectedTo) > 0 {
		return false // 版本晚于受影响结束版本
	}

	if v.FixedVersion != "" && compareVersions(version, v.FixedVersion) >= 0 {
		return false // 版本已经修复
	}

	return true
}

// extractServiceAndVersion 从服务信息中提取服务名称和版本
func extractServiceAndVersion(serviceInfo string) (string, string) {
	// 处理VMware服务
	vmwareRegex := regexp.MustCompile(`VMware Authentication Daemon Version ([0-9.]+)`)
	if matches := vmwareRegex.FindStringSubmatch(serviceInfo); len(matches) > 1 {
		return "VMware Authentication Daemon", matches[1]
	}

	// 处理SMB服务
	smbRegex := regexp.MustCompile(`SMB(?: \(.*?(\d+\.\d+.*?)\))?`)
	if matches := smbRegex.FindStringSubmatch(serviceInfo); len(matches) > 0 {
		if len(matches) > 1 && matches[1] != "" {
			return "SMB", matches[1]
		}
		return "SMB", ""
	}

	// 处理其他服务
	// 匹配 (version) 格式的版本信息
	regex := regexp.MustCompile(`\((.*?)\)`)
	matches := regex.FindStringSubmatch(serviceInfo)

	if len(matches) > 1 {
		// 提取服务名称（去掉版本部分）
		serviceName := strings.TrimSpace(regex.ReplaceAllString(serviceInfo, ""))
		// 清理版本字符串
		version := matches[1]
		return serviceName, version
	}

	// 如果没有版本信息，返回原始服务名称和空字符串
	return serviceInfo, ""
}

// checkVulnerabilityFeature 基于特征检测漏洞
func (s *VulnScanner) checkVulnerabilityFeature(host string, port int, regex string) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		s.logger.Logf("连接到 %s:%d 失败: %v", host, port, err)
		return false
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	// 读取服务Banner
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		// 如果读取失败，尝试发送特定请求
		switch port {
		case 80, 8080, 8081:
			// HTTP请求
			conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
			n, _ = conn.Read(buffer)
		case 445:
			// SMB协商请求
			conn.Write([]byte{
				0x00, 0x00, 0x00, 0x85, // NetBIOS session header
				0xFF, 0x53, 0x4D, 0x42, // SMB header: SMB\n
				0x72,                   // Command: Negotiate Protocol
				0x00, 0x00, 0x00, 0x00, // Status
				0x18,       // Flags
				0x53, 0xC8, // Flags2
				0x00, 0x00, // PID High
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security
				0x00, 0x00, // Reserved
				0x00, 0x00, 0x00, 0x00, // TID
				0x00, 0x00, // PID Low
				0x00, 0x00, // UID
				0x00, 0x00, // MID
				0x00,       // Word Count
				0x00, 0x00, // Byte Count
			})
			n, _ = conn.Read(buffer)
		default:
			// 通用请求
			conn.Write([]byte("HELLO\r\n"))
			n, _ = conn.Read(buffer)
		}
	}

	if n > 0 {
		response := string(buffer[:n])
		s.logger.Logf("从 %s:%d 读取到响应: %s", host, port, strings.TrimSpace(response))

		// 尝试直接匹配服务信息
		if strings.Contains(response, regex) {
			s.logger.Logf("检测到漏洞特征: %s", regex)
			return true
		}

		// 服务类型检测
		if port == 445 && (strings.Contains(response, "SMB") || strings.Contains(response, "NT LM")) {
			s.logger.Logf("检测到SMB服务，存在潜在漏洞风险")
			return true
		} else if (port == 902 || port == 912) && strings.Contains(response, "VMware") {
			s.logger.Logf("检测到VMware服务，存在潜在漏洞风险")
			return true
		} else if port == 135 && (strings.Contains(response, "RPC") || strings.Contains(response, "DCOM")) {
			s.logger.Logf("检测到DCE/RPC服务，存在潜在漏洞风险")
			return true
		} else if port == 22 && strings.Contains(response, "SSH") {
			s.logger.Logf("检测到SSH服务，存在潜在漏洞风险")
			return true
		} else if (port == 80 || port == 443 || port == 8080) && (strings.Contains(response, "HTTP") || strings.Contains(response, "Apache") || strings.Contains(response, "nginx")) {
			s.logger.Logf("检测到Web服务，存在潜在漏洞风险")
			return true
		}
	}

	return false
}

// DetectVulnerability 检测漏洞是否真实存在
func (s *VulnScanner) DetectVulnerability(host string, port int, vuln Vulnerability) bool {
	serviceInfo := s.services[host][port]
	serviceName, version := extractServiceAndVersion(serviceInfo)

	// 打印调试信息
	s.logger.Logf("检测漏洞 %s - %s，服务名称: %s，版本: %s，检测方法: %s",
		vuln.CVE, vuln.Name, serviceName, version, vuln.CheckMethod)

	switch vuln.CheckMethod {
	// 修复版本检测逻辑，降低误报率
	case "version":
		// 对于版本检测，尝试从服务信息中提取版本
		if version == "" {
			// 如果没有提取到版本，尝试从Banner中获取
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, s.timeout)
			if err == nil {
				defer conn.Close()
				buffer := make([]byte, 2048)
				n, _ := conn.Read(buffer)
				if n > 0 {
					banner := string(buffer[:n])
					_, extractedVersion := extractServiceAndVersion(banner)
					if extractedVersion != "" {
						version = extractedVersion
					}
				}
			}
		}
		// 修复：版本未知时不再默认认为受影响，而是基于其他特征判断
		if version == "" {
			// 对于版本未知的情况，只在有明确特征匹配时才认为受影响
			s.logger.Logf("服务版本未知，无法确定是否受漏洞影响: %s - %s", vuln.CVE, vuln.Name)
			return false
		}
		return vuln.IsAffected(version)

	case "feature":
		if vuln.DetectionRegex != "" {
			return s.checkVulnerabilityFeature(host, port, vuln.DetectionRegex)
		}
		// 如果没有检测正则，直接检查服务类型
		serviceType := serviceName
		if strings.Contains(serviceInfo, "VMware") {
			serviceType = "VMware"
		} else if strings.Contains(serviceInfo, "SMB") {
			serviceType = "SMB"
		} else if strings.Contains(serviceInfo, "SSH") {
			serviceType = "SSH"
		} else if strings.Contains(serviceInfo, "HTTP") {
			serviceType = "HTTP"
		} else if strings.Contains(serviceInfo, "RPC") || port == 135 {
			serviceType = "DCE/RPC"
		}

		if vuln.Service == serviceType || (vuln.Port == port) {
			s.logger.Logf("基于服务类型/端口检测到漏洞: %s - %s", vuln.CVE, vuln.Name)
			return true
		}
		return false
	case "exploit":
		// 简单的漏洞利用检测（仅用于教育目的）
		s.logger.Logf("不执行实际漏洞利用检测: %s", vuln.CVE)
		return false
	default:
		return false
	}
}

// Scan 扫描漏洞
func (s *VulnScanner) Scan() (interface{}, error) {
	vulnResult := make(map[string][]Vulnerability)
	s.logger.Log("漏洞扫描开始")

	var wg sync.WaitGroup
	var mu sync.Mutex

	// 遍历每个在线主机及其开放端口
	for host, ports := range s.targets {
		s.logger.Logf("开始扫描主机%s的漏洞，开放端口：%v", host, ports)

		// 检查services中是否包含该主机
		if _, hostExists := s.services[host]; !hostExists {
			s.logger.Logf("主机%s在services中不存在", host)
			continue
		}

		// 扫描每个开放端口的漏洞
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()

				// 检查端口是否在services中存在
				if _, portExists := s.services[h][p]; !portExists {
					s.logger.Logf("主机%s的端口%d在services中不存在", h, p)
					return
				}

				serviceInfo := s.services[h][p]
				s.logger.Logf("扫描主机%s:%d，服务信息：%s", h, p, serviceInfo)

				// 从服务信息中提取服务名称和版本
				serviceName, version := extractServiceAndVersion(serviceInfo)
				s.logger.Logf("提取服务名称：%s，版本：%s", serviceName, version)

				// 查找该服务可能存在的漏洞
				foundVulns := false

				// 1. 尝试精确匹配服务名称
				if vulnerabilities, exists := s.vulnDatabase[serviceName]; exists {
					foundVulns = true
					s.logger.Logf("服务%s存在漏洞记录，共%d个漏洞", serviceName, len(vulnerabilities))
					for _, vuln := range vulnerabilities {
						if vuln.Port == 0 || vuln.Port == p {
							// 检测漏洞是否真实存在
							if s.DetectVulnerability(h, p, vuln) {
								// 检测到真实漏洞
								s.logger.Logf("%s:%d 检测到漏洞 %s - %s (版本 %s 受影响)", h, p, vuln.CVE, vuln.Name, version)
								mu.Lock()
								vulnResult[h] = append(vulnResult[h], vuln)
								mu.Unlock()
							} else {
								s.logger.Logf("%s:%d 漏洞 %s - %s 不影响当前版本或特征不匹配", h, p, vuln.CVE, vuln.Name)
							}
						}
					}
				}

				// 2. 如果没有找到，尝试基于端口的漏洞检测
				portKey := fmt.Sprintf("PORT_%d", p)
				if portVulns, exists := s.vulnDatabase[portKey]; exists {
					s.logger.Logf("端口级漏洞%s存在记录，共%d个漏洞", portKey, len(portVulns))
					for _, vuln := range portVulns {
						// 检测漏洞是否真实存在
						if s.DetectVulnerability(h, p, vuln) {
							s.logger.Logf("%s:%d 检测到端口级漏洞 %s - %s", h, p, vuln.CVE, vuln.Name)
							mu.Lock()
							vulnResult[h] = append(vulnResult[h], vuln)
							mu.Unlock()
						}
					}
					foundVulns = true
				}

				// 3. 尝试匹配关键词
				if !foundVulns {
					for dbServiceName, vulnerabilities := range s.vulnDatabase {
						if dbServiceName != "PORT_445" && dbServiceName != "PORT_902" && dbServiceName != "PORT_912" && !strings.HasPrefix(dbServiceName, "PORT_") {
							if strings.Contains(serviceName, dbServiceName) || strings.Contains(dbServiceName, serviceName) || strings.Contains(serviceInfo, dbServiceName) {
								s.logger.Logf("关键词匹配服务%s和数据库服务%s，共%d个漏洞", serviceName, dbServiceName, len(vulnerabilities))
								for _, vuln := range vulnerabilities {
									if vuln.Port == 0 || vuln.Port == p {
										// 检测漏洞是否真实存在
										if s.DetectVulnerability(h, p, vuln) {
											s.logger.Logf("%s:%d 检测到漏洞 %s - %s (关键词匹配)", h, p, vuln.CVE, vuln.Name)
											mu.Lock()
											vulnResult[h] = append(vulnResult[h], vuln)
											mu.Unlock()
										}
									}
								}
								foundVulns = true
							}
						}
					}
				}

				// 4. 如果仍然没有找到，尝试通用漏洞检测
				if !foundVulns && (serviceName == "Unknown" || serviceName == "Unknown (no banner returned)") {
					// 对未知服务尝试基于端口的通用漏洞检测
					s.logger.Logf("服务未知，尝试通用漏洞检测: %s:%d", h, p)

					// 检查是否是常见端口
					commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5432, 6379, 8080}
					for _, commonPort := range commonPorts {
						if p == commonPort {
							portKey := fmt.Sprintf("PORT_%d", commonPort)
							if portVulns, exists := s.vulnDatabase[portKey]; exists {
								for _, vuln := range portVulns {
									if s.DetectVulnerability(h, p, vuln) {
										s.logger.Logf("%s:%d 检测到通用漏洞 %s - %s", h, p, vuln.CVE, vuln.Name)
										mu.Lock()
										vulnResult[h] = append(vulnResult[h], vuln)
										mu.Unlock()
									}
								}
							}
						}
					}
				}
			}(host, port)
		}
	}

	wg.Wait()
	s.logger.Logf("漏洞扫描结束，共检测到%d个主机的漏洞", len(vulnResult))
	return vulnResult, nil
}

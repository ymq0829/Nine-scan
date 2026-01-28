package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example.com/project/controller"
)

// ServiceFingerprint 服务指纹结构体
type ServiceFingerprint struct {
	ServiceName    string            `json:"service_name"`    // 服务名称
	ServiceVersion string            `json:"service_version"` // 服务版本
	Protocol       string            `json:"protocol"`        // 协议类型 (TCP/UDP)
	Port           int               `json:"port"`            // 端口号
	Banner         string            `json:"banner"`          // 原始Banner
	Fingerprint    string            `json:"fingerprint"`     // 指纹特征
	Confidence     int               `json:"confidence"`      // 识别置信度 (0-100)
	Metadata       map[string]string `json:"metadata"`        // 额外元数据
}

// ProtocolDetector 协议交互探测器
type ProtocolDetector struct {
	timeout time.Duration
	logger  *controller.Logger
}

// NewProtocolDetector 创建协议探测器
func NewProtocolDetector(logger *controller.Logger) *ProtocolDetector {
	return &ProtocolDetector{
		timeout: 5 * time.Second,
		logger:  logger,
	}
}

// DetectService 主动协议交互探测服务
func (d *ProtocolDetector) DetectService(host string, port int) *ServiceFingerprint {
	// 根据端口选择探测策略
	switch port {
	case 80, 8080, 8081, 443:
		return d.detectHTTP(host, port)
	case 22:
		return d.detectSSH(host, port)
	case 3306:
		return d.detectMySQL(host, port)
	case 21:
		return d.detectFTP(host, port)
	case 25:
		return d.detectSMTP(host, port)
	case 53:
		return d.detectDNS(host, port)
	case 1433:
		return d.detectMSSQL(host, port)
	case 5432:
		return d.detectPostgreSQL(host, port)
	case 3389:
		return d.detectRDP(host, port)
	default:
		return d.detectGeneric(host, port)
	}
}

// detectHTTP HTTP/HTTPS服务探测
func (d *ProtocolDetector) detectHTTP(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	// 尝试HTTP连接
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// 发送HTTP请求
	httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ServiceScanner/1.0\r\nAccept: */*\r\n\r\n", host)
	conn.SetWriteDeadline(time.Now().Add(d.timeout))
	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	// 读取响应
	conn.SetReadDeadline(time.Now().Add(d.timeout))
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	fingerprint.Banner = strings.TrimSpace(response)
	fingerprint.Metadata["raw_response"] = response

	// 分析HTTP响应
	if strings.Contains(strings.ToUpper(response), "HTTP") {
		fingerprint.ServiceName = "HTTP Server"
		fingerprint.Confidence = 85

		// 提取服务器信息
		if strings.Contains(response, "Apache") {
			fingerprint.ServiceName = "Apache HTTP Server"
			fingerprint.Fingerprint = "Apache"
		} else if strings.Contains(response, "nginx") {
			fingerprint.ServiceName = "Nginx HTTP Server"
			fingerprint.Fingerprint = "Nginx"
		} else if strings.Contains(response, "IIS") {
			fingerprint.ServiceName = "Microsoft IIS"
			fingerprint.Fingerprint = "IIS"
		}

		// 尝试提取版本信息
		versionRegex := regexp.MustCompile(`Server:\s*([^\r\n]+)`)
		if matches := versionRegex.FindStringSubmatch(response); len(matches) > 1 {
			fingerprint.ServiceVersion = strings.TrimSpace(matches[1])
			fingerprint.Confidence = 95
		}
	}

	// 如果是443端口，标记为HTTPS
	if port == 443 {
		fingerprint.ServiceName = "HTTPS " + fingerprint.ServiceName
		fingerprint.Confidence += 5
	}

	return fingerprint
}

// detectSSH SSH服务探测
func (d *ProtocolDetector) detectSSH(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// SSH服务通常会主动发送banner
	conn.SetReadDeadline(time.Now().Add(d.timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	fingerprint.Banner = strings.TrimSpace(banner)
	fingerprint.Metadata["ssh_banner"] = banner

	// 分析SSH banner
	if strings.Contains(banner, "SSH") {
		fingerprint.ServiceName = "SSH Server"
		fingerprint.Confidence = 90

		// 提取版本信息
		versionRegex := regexp.MustCompile(`SSH-([\d.]+)-([^\s]+)`)
		if matches := versionRegex.FindStringSubmatch(banner); len(matches) > 2 {
			fingerprint.ServiceVersion = matches[1]
			fingerprint.Fingerprint = matches[2]
			fingerprint.Confidence = 98
		}
	}

	return fingerprint
}

// detectMySQL MySQL服务探测
func (d *ProtocolDetector) detectMySQL(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// MySQL握手协议初始包
	handshakePacket := []byte{
		0x0a,                               // Protocol version
		0x35, 0x2e, 0x37, 0x2e, 0x32, 0x38, // Server version "5.7.28"
		0x00, // NULL terminator
	}

	conn.SetWriteDeadline(time.Now().Add(d.timeout))
	_, err = conn.Write(handshakePacket)
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	// 读取响应
	conn.SetReadDeadline(time.Now().Add(d.timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	response := string(buffer[:n])
	fingerprint.Banner = response
	fingerprint.Metadata["mysql_response"] = response

	// 分析MySQL响应
	if strings.Contains(response, "MySQL") || n > 0 && buffer[0] == 0x0a {
		fingerprint.ServiceName = "MySQL Database"
		fingerprint.Confidence = 85

		// 尝试提取版本信息
		if idx := strings.Index(response, "5."); idx != -1 {
			end := strings.Index(response[idx:], "\x00")
			if end != -1 {
				fingerprint.ServiceVersion = response[idx : idx+end]
				fingerprint.Confidence = 95
			}
		}
	}

	return fingerprint
}

// detectFTP FTP服务探测
func (d *ProtocolDetector) detectFTP(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// 读取FTP欢迎消息
	conn.SetReadDeadline(time.Now().Add(d.timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	fingerprint.Banner = strings.TrimSpace(banner)
	fingerprint.Metadata["ftp_banner"] = banner

	// 分析FTP响应
	if strings.HasPrefix(banner, "220") {
		fingerprint.ServiceName = "FTP Server"
		fingerprint.Confidence = 90

		// 提取服务器信息
		if strings.Contains(strings.ToLower(banner), "vsftpd") {
			fingerprint.ServiceName = "vsftpd"
			fingerprint.Fingerprint = "vsftpd"
		} else if strings.Contains(strings.ToLower(banner), "proftpd") {
			fingerprint.ServiceName = "ProFTPD"
			fingerprint.Fingerprint = "ProFTPD"
		} else if strings.Contains(strings.ToLower(banner), "filezilla") {
			fingerprint.ServiceName = "FileZilla Server"
			fingerprint.Fingerprint = "FileZilla"
		}

		// 发送SYST命令获取系统信息
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		conn.Write([]byte("SYST\r\n"))
		conn.SetReadDeadline(time.Now().Add(d.timeout))
		systResponse, _ := reader.ReadString('\n')
		fingerprint.Metadata["syst_response"] = systResponse
	}

	return fingerprint
}

// detectSMTP SMTP服务探测
func (d *ProtocolDetector) detectSMTP(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// 读取SMTP欢迎消息
	conn.SetReadDeadline(time.Now().Add(d.timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	fingerprint.Banner = strings.TrimSpace(banner)
	fingerprint.Metadata["smtp_banner"] = banner

	// 分析SMTP响应
	if strings.HasPrefix(banner, "220") {
		fingerprint.ServiceName = "SMTP Server"
		fingerprint.Confidence = 90

		// 识别具体SMTP服务器
		bannerLower := strings.ToLower(banner)
		if strings.Contains(bannerLower, "postfix") {
			fingerprint.ServiceName = "Postfix SMTP"
			fingerprint.Fingerprint = "Postfix"
		} else if strings.Contains(bannerLower, "sendmail") {
			fingerprint.ServiceName = "Sendmail"
			fingerprint.Fingerprint = "Sendmail"
		} else if strings.Contains(bannerLower, "exim") {
			fingerprint.ServiceName = "Exim SMTP"
			fingerprint.Fingerprint = "Exim"
		} else if strings.Contains(bannerLower, "microsoft") {
			fingerprint.ServiceName = "Microsoft SMTP"
			fingerprint.Fingerprint = "Microsoft"
		}

		// 发送EHLO命令获取更多信息
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		conn.Write([]byte("EHLO scanner.example.com\r\n"))
		conn.SetReadDeadline(time.Now().Add(d.timeout))

		// 读取多行响应
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "250 ") {
				break
			}
			fingerprint.Metadata["ehlo_response"] += line
		}
	}

	return fingerprint
}

// detectDNS DNS服务探测
func (d *ProtocolDetector) detectDNS(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "UDP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	// DNS查询包 (查询 example.com 的A记录)
	dnsQuery := []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
		0x03, 'c', 'o', 'm', // "com"
		0x00,       // End of name
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(d.timeout))
	_, err = conn.Write(dnsQuery)
	if err != nil {
		return fingerprint
	}

	conn.SetReadDeadline(time.Now().Add(d.timeout))
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err == nil && n > 0 {
		fingerprint.ServiceName = "DNS Server"
		fingerprint.Confidence = 95
		fingerprint.Metadata["dns_response_size"] = strconv.Itoa(n)
	}

	return fingerprint
}

// detectMSSQL Microsoft SQL Server探测
func (d *ProtocolDetector) detectMSSQL(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// TDS协议预登录包
	tdsPacket := []byte{
		0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
		0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
		0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x24, 0x00,
		0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(d.timeout))
	_, err = conn.Write(tdsPacket)
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	conn.SetReadDeadline(time.Now().Add(d.timeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err == nil && n > 0 {
		fingerprint.ServiceName = "Microsoft SQL Server"
		fingerprint.Confidence = 90
		fingerprint.Metadata["mssql_response"] = "TDS protocol detected"
	}

	return fingerprint
}

// detectPostgreSQL PostgreSQL服务探测
func (d *ProtocolDetector) detectPostgreSQL(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// PostgreSQL启动消息
	startupMessage := make([]byte, 8)
	binary.BigEndian.PutUint32(startupMessage[0:4], 8)      // 长度
	binary.BigEndian.PutUint32(startupMessage[4:8], 196608) // 协议版本 3.0

	conn.SetWriteDeadline(time.Now().Add(d.timeout))
	_, err = conn.Write(startupMessage)
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	conn.SetReadDeadline(time.Now().Add(d.timeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err == nil && n > 0 {
		fingerprint.ServiceName = "PostgreSQL Database"
		fingerprint.Confidence = 90
		fingerprint.Metadata["postgresql_response"] = "PostgreSQL protocol detected"
	}

	return fingerprint
}

// detectRDP RDP服务探测
func (d *ProtocolDetector) detectRDP(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	// RDP连接请求
	rdpRequest := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
		0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(d.timeout))
	_, err = conn.Write(rdpRequest)
	if err != nil {
		return d.fallbackToBanner(conn, port)
	}

	conn.SetReadDeadline(time.Now().Add(d.timeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err == nil && n > 0 {
		fingerprint.ServiceName = "RDP (Remote Desktop Protocol)"
		fingerprint.Confidence = 95
		fingerprint.Metadata["rdp_response"] = "RDP protocol detected"
	}

	return fingerprint
}

// detectGeneric 通用服务探测
func (d *ProtocolDetector) detectGeneric(host string, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d.timeout)
	if err != nil {
		fingerprint.ServiceName = "Unknown (connection failed)"
		return fingerprint
	}
	defer conn.Close()

	return d.fallbackToBanner(conn, port)
}

// fallbackToBanner 回退到基本的Banner抓取和端口识别
func (d *ProtocolDetector) fallbackToBanner(conn net.Conn, port int) *ServiceFingerprint {
	fingerprint := &ServiceFingerprint{
		Port:       port,
		Protocol:   "TCP",
		Metadata:   make(map[string]string),
		Confidence: 0,
	}

	// 尝试读取banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		fingerprint.ServiceName = "Unknown (no banner)"
		return fingerprint
	}

	fingerprint.Banner = strings.TrimSpace(banner)
	fingerprint.ServiceName = "Unknown Service"
	fingerprint.Confidence = 0

	// 基于端口号的预识别（提高基础识别准确率）
	switch port {
	case 22:
		fingerprint.ServiceName = "SSH Service"
		fingerprint.Confidence = 90
	case 80, 8080, 8081:
		fingerprint.ServiceName = "HTTP Service"
		fingerprint.Confidence = 85
	case 443:
		fingerprint.ServiceName = "HTTPS Service"
		fingerprint.Confidence = 95
	case 3306:
		fingerprint.ServiceName = "MySQL Database"
		fingerprint.Confidence = 85
	case 21:
		fingerprint.ServiceName = "FTP Service"
		fingerprint.Confidence = 80
	case 25:
		fingerprint.ServiceName = "SMTP Service"
		fingerprint.Confidence = 80
	case 53:
		fingerprint.ServiceName = "DNS Server"
		fingerprint.Confidence = 95
	case 1433:
		fingerprint.ServiceName = "Microsoft SQL Server"
		fingerprint.Confidence = 90
	case 5432:
		fingerprint.ServiceName = "PostgreSQL Database"
		fingerprint.Confidence = 90
	case 3389:
		fingerprint.ServiceName = "RDP Service"
		fingerprint.Confidence = 95
	default:
		fingerprint.ServiceName = "Unknown Service"
		fingerprint.Confidence = 30
	}

	// 基于Banner内容的增强识别（覆盖端口识别结果）
	if banner != "" {
		bannerUpper := strings.ToUpper(banner)
		switch {
		case strings.Contains(bannerUpper, "HTTP"):
			fingerprint.ServiceName = "HTTP Service"
			fingerprint.Confidence = max(fingerprint.Confidence, 70)
		case strings.Contains(banner, "SSH"):
			fingerprint.ServiceName = "SSH Service"
			fingerprint.Confidence = max(fingerprint.Confidence, 80)
		case strings.Contains(banner, "FTP"):
			fingerprint.ServiceName = "FTP Service"
			fingerprint.Confidence = max(fingerprint.Confidence, 75)
		case strings.Contains(banner, "SMTP"):
			fingerprint.ServiceName = "SMTP Service"
			fingerprint.Confidence = max(fingerprint.Confidence, 75)
		case strings.Contains(banner, "MYSQL"):
			fingerprint.ServiceName = "MySQL Database"
			fingerprint.Confidence = max(fingerprint.Confidence, 80)
		case strings.Contains(banner, "APACHE"):
			fingerprint.ServiceName = "Apache HTTP Server"
			fingerprint.Confidence = max(fingerprint.Confidence, 85)
		case strings.Contains(banner, "NGINX"):
			fingerprint.ServiceName = "Nginx HTTP Server"
			fingerprint.Confidence = max(fingerprint.Confidence, 85)
		}
	}

	return fingerprint
}

// max 辅助函数，返回两个整数中的较大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ServiceScanner 服务扫描器
type ServiceScanner struct {
	targets          map[string][]int   // key: 主机IP, value: 开放端口列表
	timeout          time.Duration      // 连接超时时间
	logger           *controller.Logger // 新增：日志记录器
	protocolDetector *ProtocolDetector  // 新增：协议探测器
}

// NewServiceScanner 初始化服务扫描器
func NewServiceScanner(openPorts map[string][]int, logger *controller.Logger) *ServiceScanner {
	return &ServiceScanner{
		targets:          openPorts,
		timeout:          5 * time.Second, // 5秒超时
		logger:           logger,
		protocolDetector: NewProtocolDetector(logger),
	}
}

// Scan 扫描开放端口对应的服务类型
func (s *ServiceScanner) Scan() (interface{}, error) {
	serviceResult := make(map[string]map[int]*ServiceFingerprint) // 修改为返回指纹结构体
	s.logger.Log("服务扫描开始 - 使用指纹识别模式")

	// 遍历每个在线主机及其开放端口
	for host, ports := range s.targets {
		s.logger.Logf("开始扫描主机%s的服务，开放端口数: %d", host, len(ports))
		hostServices := make(map[int]*ServiceFingerprint)
		// 在Scan方法中添加过滤逻辑
		for _, port := range ports {
			fingerprint := s.protocolDetector.DetectService(host, port)

			// 过滤低置信度结果（建议阈值设为30%）
			if fingerprint.Confidence >= 30 {
				hostServices[port] = fingerprint
				s.logger.Logf("%s:%d 识别为: %s (置信度: %d%%)",
					host, port, fingerprint.ServiceName, fingerprint.Confidence)
			} else {
				s.logger.Logf("%s:%d 服务识别置信度过低(%d%%)，已过滤",
					host, port, fingerprint.Confidence)
			}
		}
		serviceResult[host] = hostServices
		s.logger.Logf("%s 服务扫描完成", host)
	}

	s.logger.Log("服务扫描结束")
	return serviceResult, nil
}

// GetServiceFingerprint 获取服务的详细指纹信息
func (s *ServiceScanner) GetServiceFingerprint(host string, port int) *ServiceFingerprint {
	return s.protocolDetector.DetectService(host, port)
}

// EnhancedScan 增强扫描模式，返回更详细的信息
func (s *ServiceScanner) EnhancedScan() (map[string]map[int]*ServiceFingerprint, error) {
	s.logger.Log("启动增强服务扫描模式")
	result, err := s.Scan()
	if err != nil {
		return nil, err
	}
	return result.(map[string]map[int]*ServiceFingerprint), nil
}

// ServiceScanResult 封装服务扫描结果
type ServiceScanResult struct {
	ServiceInfo map[string]map[int]*ServiceFingerprint // 主机 -> 端口 -> 服务指纹
}

// GetServices 返回指定主机的服务映射（端口->服务名称）
func (r *ServiceScanResult) GetServices(host string) map[string]string {
	services := make(map[string]string)
	if portMap, exists := r.ServiceInfo[host]; exists {
		for port, fingerprint := range portMap {
			services[strconv.Itoa(port)] = fingerprint.ServiceName
		}
	}
	return services
}

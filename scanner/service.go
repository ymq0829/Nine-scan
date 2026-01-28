package scanner

import (
	"bufio"
	"net"
	"strings"
	"time"

	"example.com/project/controller" // 引入日志模块
)

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
		for _, port := range ports {
			// 使用协议探测器进行主动探测
			fingerprint := s.protocolDetector.DetectService(host, port)
			hostServices[port] = fingerprint

			s.logger.Logf("%s:%d 识别为: %s (置信度: %d%%)",
				host, port, fingerprint.ServiceName, fingerprint.Confidence)
		}
		serviceResult[host] = hostServices
		s.logger.Logf("%s 服务扫描完成", host)
	}

	s.logger.Log("服务扫描结束")
	return serviceResult, nil
}

// getServiceBanner 根据连接和端口抓取并识别服务Banner（保留向后兼容）
func (s *ServiceScanner) getServiceBanner(conn net.Conn, port int) string {
	// 针对常见端口提前预判，提高识别准确率
	switch port {
	case 80, 8080, 8081:
		// 发送HTTP请求头，触发服务响应
		_, _ = conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	case 22:
		// SSH服务通常会主动发送Banner，直接读取即可
	case 3306:
		// MySQL端口，读取初始响应
	case 443:
		// HTTPS服务，简单识别
		_, _ = conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	case 21:
		// FTP服务
	case 25:
		// SMTP服务
	}

	// 设置读取超时
	_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
	scanner := bufio.NewScanner(conn)
	scanner.Scan()
	banner := strings.TrimSpace(scanner.Text())

	// 根据Banner特征识别服务
	return s.recognizeServiceByBanner(banner, port)
}

// recognizeServiceByBanner 基于Banner内容和端口识别服务类型（保留向后兼容）
func (s *ServiceScanner) recognizeServiceByBanner(banner string, port int) string {
	// 使用新的指纹匹配功能
	match := MatchFingerprint(banner, port)

	if match.Confidence >= 80 {
		if match.Version != "" {
			return match.Service + " " + match.Version
		}
		return match.Service
	}

	// 回退到原有逻辑
	switch {
	case strings.Contains(banner, "SSH") || port == 22:
		return "SSH (Secure Shell)"
	case strings.Contains(banner, "HTTP") || port == 80 || port == 8080 || port == 8081:
		return "HTTP/HTTPS Web Service"
	case strings.Contains(banner, "MySQL") || port == 3306:
		return "MySQL Database"
	case strings.Contains(banner, "FTP") || port == 21:
		return "FTP (File Transfer Protocol)"
	case strings.Contains(banner, "SMTP") || port == 25:
		return "SMTP (Simple Mail Transfer Protocol)"
	case port == 443:
		return "HTTPS (Secure Web Service)"
	case port == 3389:
		return "RDP (Remote Desktop Protocol)"
	case banner == "":
		return "Unknown (no banner returned)"
	default:
		return "Unknown: " + banner
	}
}

// GetServiceFingerprint 获取服务的详细指纹信息（新增方法）
func (s *ServiceScanner) GetServiceFingerprint(host string, port int) *ServiceFingerprint {
	return s.protocolDetector.DetectService(host, port)
}

// EnhancedScan 增强扫描模式，返回更详细的信息（新增方法）
func (s *ServiceScanner) EnhancedScan() (map[string]map[int]*ServiceFingerprint, error) {
	s.logger.Log("启动增强服务扫描模式")
	result, err := s.Scan()
	if err != nil {
		return nil, err
	}
	return result.(map[string]map[int]*ServiceFingerprint), nil
}

// filterNonASCII 过滤非ASCII字符，解决乱码问题（改进版）
func filterNonASCII(s string) string {
	var result strings.Builder
	for _, r := range s {
		// 放宽过滤条件，保留更多可读字符
		if r >= 32 && r <= 126 { // 保留基本ASCII可打印字符
			result.WriteRune(r)
		} else if r >= 0x80 && r <= 0x9F { // 过滤Windows-1252控制字符
			// 跳过这些控制字符，它们通常会导致乱码
		} else if r >= 0xA0 && r <= 0xFF { // 保留扩展拉丁字符
			result.WriteRune(r)
		} else if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			result.WriteRune(r) // 保留空白字符
		} else if r >= 0x4E00 && r <= 0x9FFF { // 保留中文字符
			result.WriteRune(r)
		}
		// 其他特殊字符被过滤掉
	}
	return result.String()
}

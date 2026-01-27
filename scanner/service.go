package scanner

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"

	"example.com/project/controller" // 引入日志模块
)

// ServiceScanner 服务扫描器
type ServiceScanner struct {
	targets map[string][]int   // key: 主机IP, value: 开放端口列表
	timeout time.Duration      // 连接超时时间
	logger  *controller.Logger // 新增：日志记录器
}

// NewServiceScanner 初始化服务扫描器
func NewServiceScanner(openPorts map[string][]int, logger *controller.Logger) *ServiceScanner {
	return &ServiceScanner{
		targets: openPorts,
		timeout: 5 * time.Second, // 5秒超时
		logger:  logger,
	}
}

// Scan 扫描开放端口对应的服务类型
func (s *ServiceScanner) Scan() (interface{}, error) {
	serviceResult := make(map[string]map[int]string)
	s.logger.Log("服务扫描开始")

	// 遍历每个在线主机及其开放端口
	for host, ports := range s.targets {
		s.logger.Logf("开始扫描主机%s的服务，开放端口数: %d", host, len(ports))
		hostServices := make(map[int]string)
		for _, port := range ports {
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			// 建立TCP连接
			conn, err := net.DialTimeout("tcp", addr, s.timeout)
			if err != nil {
				hostServices[port] = "Unknown (connection failed)"
				s.logger.Logf("%s:%d 服务识别失败: %v", host, port, err)
				continue
			}

			// 抓取服务Banner
			serviceName := s.getServiceBanner(conn, port)
			hostServices[port] = serviceName
			s.logger.Logf("%s:%d 识别为: %s", host, port, serviceName)
			conn.Close() // 立即关闭连接，避免defer在循环中的问题
		}
		serviceResult[host] = hostServices
		s.logger.Logf("%s 服务扫描完成", host)
	}

	s.logger.Log("服务扫描结束")
	return serviceResult, nil
}

// getServiceBanner 根据连接和端口抓取并识别服务Banner
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

// recognizeServiceByBanner 基于Banner内容和端口识别服务类型
func (s *ServiceScanner) recognizeServiceByBanner(banner string, port int) string {
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

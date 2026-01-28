package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"example.com/project/controller"
)

type OSDetector struct {
	Logger      *controller.Logger
	PortScanner *PortScanner
	ServiceScan *ServiceScanner
}

func NewOSDetector(logger *controller.Logger, portScanner *PortScanner, serviceScan *ServiceScanner) *OSDetector {
	return &OSDetector{
		Logger:      logger,
		PortScanner: portScanner,
		ServiceScan: serviceScan,
	}
}

// DetectWithTTL 根据ICMP扫描阶段获取的TTL值识别操作系统
func (d *OSDetector) DetectWithTTL(hostInfos []HostInfo) (interface{}, error) {
	osInfo := make(map[string]string)

	for _, hostInfo := range hostInfos {
		d.Logger.Logf("开始检测主机 %s 的操作系统", hostInfo.Host)

		if !hostInfo.Alive {
			d.Logger.Logf("主机 %s 不在线，跳过操作系统检测", hostInfo.Host)
			osInfo[hostInfo.Host] = "Unknown (主机不在线)"
			continue
		}

		// 如果TTL为-1，表示ICMP探测失败，无法获取TTL值
		if hostInfo.TTL == -1 {
			d.Logger.Logf("主机 %s ICMP探测失败，TTL未知，使用智能检测", hostInfo.Host)
			osInfo[hostInfo.Host] = d.detectOSIntelligently(hostInfo.Host)
			continue
		}

		// 如果TTL为0，表示TCP扫描的结果（兼容旧代码）
		if hostInfo.TTL == 0 {
			d.Logger.Logf("主机 %s TTL未知，使用智能检测", hostInfo.Host)
			osInfo[hostInfo.Host] = d.detectOSIntelligently(hostInfo.Host)
			continue
		}

		// 根据TTL值判断操作系统
		osInfo[hostInfo.Host] = d.detectOSByTTL(hostInfo.TTL)
		d.Logger.Logf("主机 %s 操作系统检测结果: %s", hostInfo.Host, osInfo[hostInfo.Host])
	}
	return osInfo, nil
}

// Detect 兼容旧接口，保持向后兼容
func (d *OSDetector) Detect(aliveHosts []string) (interface{}, error) {
	// 将字符串切片转换为HostInfo切片（TTL设为0）
	var hostInfos []HostInfo
	for _, host := range aliveHosts {
		hostInfos = append(hostInfos, HostInfo{
			Host:  host,
			Alive: true,
			TTL:   0,
		})
	}
	return d.DetectWithTTL(hostInfos)
}

// detectOSByTTL 根据TTL值判断操作系统
// 优化detectOSByTTL方法，提供更精确的TTL识别
func (d *OSDetector) detectOSByTTL(ttl int) string {
	// 根据常见的操作系统初始TTL值进行判断
	switch {
	case ttl == 64 || ttl == 255:
		return "Linux/Unix"
	case ttl == 128:
		return "Windows"
	case ttl == 30 || ttl == 60: // Cisco设备常见TTL
		return "Network Device (Cisco)"
	case ttl == 254: // 某些网络设备
		return "Network Device"
	case ttl >= 50 && ttl <= 70: // 经过几跳的Linux系统
		return "Linux/Unix (远程)"
	case ttl >= 110 && ttl <= 125: // 经过几跳的Windows系统
		return "Windows (远程)"
	default:
		// 根据TTL值范围进行智能猜测
		if ttl < 64 {
			return "Linux/Unix (TTL衰减)"
		} else if ttl < 128 {
			return "Windows (TTL衰减)"
		} else {
			return fmt.Sprintf("Unknown (TTL: %d)", ttl)
		}
	}
}

// detectOSByTCP 通过TCP连接特征判断操作系统（后备方法）
func (d *OSDetector) detectOSByTCP(host string) string {
	// 尝试连接常见端口来判断操作系统特征
	ports := []struct {
		port   int
		osHint string
	}{
		{445, "Windows"},   // SMB服务
		{3389, "Windows"},  // RDP服务
		{22, "Linux/Unix"}, // SSH服务
		{21, "Unknown"},    // FTP服务
	}

	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p.port), 2*time.Second)
		if err == nil {
			conn.Close()
			return p.osHint
		}
	}

	return "Unknown"
}

// detectOSIntelligently 智能检测操作系统（当TTL未知时使用）
func (d *OSDetector) detectOSIntelligently(host string) string {
	// 首先尝试使用端口和服务信息检测
	if d.PortScanner != nil && d.ServiceScan != nil {
		osByPorts := d.detectOSByPortsAndServices(host)
		if osByPorts != "Unknown" {
			return osByPorts + " (端口服务检测)"
		}
	}

	// 如果端口服务检测失败，尝试TCP端口检测
	osByTCP := d.detectOSByTCP(host)
	if osByTCP != "Unknown" {
		return osByTCP + " (TCP检测)"
	}

	return "Unknown"
}

// detectOSByPortsAndServices 通过开放端口和服务信息检测操作系统
func (d *OSDetector) detectOSByPortsAndServices(host string) string {
	// 获取开放端口
	portResult, err := d.PortScanner.ScanHosts([]string{host})
	if err != nil {
		d.Logger.Logf("端口扫描失败: %v", err)
		return "Unknown"
	}
	compResult, ok := portResult.(*ComprehensiveScanResult)
	if !ok {
		d.Logger.Logf("端口扫描结果类型错误")
		return "Unknown"
	}
	openPorts := compResult.GetOpenPorts(host)
	if len(openPorts) == 0 {
		d.Logger.Logf("主机 %s 没有开放端口", host)
		return "Unknown"
	}

	// 获取服务信息
	openPortsMap := map[string][]int{host: openPorts}
	serviceScanner := NewServiceScanner(openPortsMap, d.Logger)
	serviceResult, err := serviceScanner.Scan()
	if err != nil {
		d.Logger.Logf("服务扫描失败: %v", err)
		return "Unknown"
	}
	servResult, ok := serviceResult.(*ServiceScanResult)
	if !ok {
		d.Logger.Logf("服务扫描结果类型错误")
		return "Unknown"
	}
	services := servResult.GetServices(host)
	if len(services) == 0 {
		d.Logger.Logf("主机 %s 没有检测到服务", host)
		return "Unknown"
	}

	// 分析端口和服务模式
	windowsPorts := 0
	linuxPorts := 0
	networkDevicePorts := 0

	for _, service := range services {
		// 检查Windows特有服务
		if strings.Contains(strings.ToLower(service), "netbios") ||
			strings.Contains(strings.ToLower(service), "microsoft-ds") ||
			strings.Contains(strings.ToLower(service), "msrpc") ||
			strings.Contains(strings.ToLower(service), "rdp") {
			windowsPorts++
		}

		// 检查Linux特有服务
		if strings.Contains(strings.ToLower(service), "ssh") ||
			strings.Contains(strings.ToLower(service), "nfs") ||
			strings.Contains(strings.ToLower(service), "x11") ||
			strings.Contains(strings.ToLower(service), "samba") {
			linuxPorts++
		}

		// 检查网络设备服务
		if strings.Contains(strings.ToLower(service), "telnet") ||
			strings.Contains(strings.ToLower(service), "snmp") ||
			strings.Contains(strings.ToLower(service), "tftp") {
			networkDevicePorts++
		}
	}

	// 根据检测到的服务模式判断操作系统
	if windowsPorts > linuxPorts && windowsPorts > networkDevicePorts {
		return "Windows"
	} else if linuxPorts > windowsPorts && linuxPorts > networkDevicePorts {
		return "Linux/Unix"
	} else if networkDevicePorts > windowsPorts && networkDevicePorts > linuxPorts {
		return "Network Device"
	}

	// 如果服务模式不明显，检查特定端口的组合
	hasSMB := false
	hasRDP := false
	hasSSH := false

	for port := range services {
		if port == "445" || port == "139" {
			hasSMB = true
		}
		if port == "3389" {
			hasRDP = true
		}
		if port == "22" {
			hasSSH = true
		}
	}

	// 典型Windows模式
	if hasSMB && hasRDP {
		return "Windows"
	}

	// 典型Linux模式
	if hasSSH && !hasSMB && !hasRDP {
		return "Linux/Unix"
	}

	return "Unknown"
}

package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"example.com/project/controller"
)

type OSDetector struct {
	Logger *controller.Logger
}

func NewOSDetector(logger *controller.Logger) *OSDetector {
	return &OSDetector{
		Logger: logger,
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

		// 如果TTL为0，表示无法获取TTL值（可能是TCP扫描的结果）
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

// 添加TTL衰减计算功能
func (d *OSDetector) estimateOriginalTTL(ttl int) int {
	// 根据接收到的TTL值估计原始TTL
	if ttl <= 30 {
		return 64 // 可能是Linux系统经过较多跳
	} else if ttl <= 64 {
		return 64 // Linux系统
	} else if ttl <= 100 {
		return 128 // Windows系统经过较多跳
	} else if ttl <= 128 {
		return 128 // Windows系统
	} else if ttl <= 200 {
		return 255 // 某些Unix系统
	} else {
		return 255 // 某些网络设备
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
	// 首先尝试TCP端口检测
	osByTCP := d.detectOSByTCP(host)
	if osByTCP != "Unknown" {
		return osByTCP + " (智能检测)"
	}

	// 如果TCP检测失败，使用其他智能方法
	// 1. 检查是否为本地网络
	if d.isLocalNetwork(host) {
		// 本地网络：根据常见配置猜测
		return "Windows (本地网络猜测)"
	}

	// 2. 检查是否为知名服务提供商
	if d.isKnownServiceProvider(host) {
		// 知名服务提供商通常使用Linux/Unix
		return "Linux/Unix (服务提供商猜测)"
	}

	// 3. 默认使用最常见的操作系统
	return "Linux/Unix (默认猜测)"
}

// isLocalNetwork 判断目标是否为本地网络
func (d *OSDetector) isLocalNetwork(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// 检查是否为私有IP地址范围
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

// isKnownServiceProvider 判断目标是否为知名服务提供商
func (d *OSDetector) isKnownServiceProvider(host string) bool {
	// 常见的服务提供商域名或IP范围
	knownProviders := []string{
		"8.8.8.8",    // Google DNS
		"1.1.1.1",    // Cloudflare DNS
		"baidu.com",  // 百度
		"google.com", // Google
	}

	// 检查是否为IP地址
	ip := net.ParseIP(host)
	if ip != nil {
		for _, provider := range knownProviders {
			if providerIP := net.ParseIP(provider); providerIP != nil {
				if ip.Equal(providerIP) {
					return true
				}
			}
		}
	}

	// 检查是否为域名
	for _, provider := range knownProviders {
		if host == provider || strings.HasSuffix(host, "."+provider) {
			return true
		}
	}

	return false
}

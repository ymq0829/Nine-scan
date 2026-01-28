package controller

import (
	"flag" // Go 语言标准库 flag ，用于解析带选项的命令行参数
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ScanParams 扫描参数结构体
type ScanParams struct {
	Targets    []string  // 目标主机列表
	Ports      []int     // 扫描端口列表
	DelayType  DelayType // 延迟类型
	DelayValue int       // 延迟基础值（ms）
	Timeout    int       // TCP连接超时时间（秒）
	EnableUDP  bool      // 启用UDP扫描
	Format     string    // 输出格式
}

// ParseInput 解析用户命令行输入
func ParseInput() (*ScanParams, error) {
	// 定义命令行参数
	targetsFlag := flag.String("targets", "", "目标主机列表，支持逗号分隔（如192.168.1.1,192.168.1.2）或网段（192.168.1.1-254）")
	portsFlag := flag.String("ports", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080", "扫描端口列表，逗号分隔（如80,443,22）或范围（21-23）")
	delayTypeFlag := flag.String("delay", "constant", "延迟类型：constant/random/function1/function2/function3/function4")
	delayValFlag := flag.Int("delayVal", 100, "延迟基础值（毫秒）")
	timeoutFlag := flag.Int("timeout", 5, "TCP连接超时时间（秒）")
	enableUDPFlag := flag.Bool("udp", true, "启用UDP扫描（默认启用）")
	formatFlag := flag.String("format", "txt", "输出格式（txt/csv/tsv/json）")

	// 解析参数
	flag.Parse()

	// 验证目标参数
	if *targetsFlag == "" {
		return nil, fmt.Errorf("必须指定目标主机（-targets参数）")
	}

	// 解析目标主机
	targets := strings.Split(*targetsFlag, ",")
	var resolvedTargets []string

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// 检查是否为IP地址范围格式（如"192.168.47.1-254"）
		if strings.Contains(t, ".") && strings.Contains(t, "-") {
			// 尝试解析为IP范围
			ips, err := parseIPRange(t)
			if err == nil {
				// 成功解析为IP范围，添加所有IP地址
				resolvedTargets = append(resolvedTargets, ips...)
				continue
			}
			// 如果不是有效的IP范围，继续其他解析方式
		}

		// 处理URL格式目标 (如 http://example.com)
		if strings.Contains(t, "://") {
			u, err := url.Parse(t)
			if err != nil {
				return nil, fmt.Errorf("解析URL目标失败: %s, 错误: %v", t, err)
			}

			// 提取主机名 (去掉端口)
			host, _, err := net.SplitHostPort(u.Host)
			if err != nil {
				host = u.Host // 无端口时直接使用Host
			}

			// 解析主机名为IP地址
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, fmt.Errorf("解析主机名失败: %s, 错误: %v", host, err)
			}

			for _, ip := range ips {
				resolvedTargets = append(resolvedTargets, ip.String())
			}
			log.Printf("解析URL目标 %s 为 %v", t, ips) // 添加调试日志
		} else {
			// 非URL目标：检查是否为IP地址
			if net.ParseIP(t) == nil {
				// 非IP地址，尝试解析为主机名
				ips, err := net.LookupIP(t)
				if err != nil {
					return nil, fmt.Errorf("解析主机名失败: %s, 错误: %v", t, err)
				}
				for _, ip := range ips {
					resolvedTargets = append(resolvedTargets, ip.String())
				}
			} else {
				// 直接是IP地址
				resolvedTargets = append(resolvedTargets, t)
			}
		}
	}

	if len(resolvedTargets) == 0 {
		return nil, fmt.Errorf("未解析到有效目标地址")
	}
	targets = resolvedTargets

	// 解析端口
	portStrs := strings.Split(*portsFlag, ",")
	var ports []int
	for _, ps := range portStrs {
		ps = strings.TrimSpace(ps)

		// 检查是否为端口范围格式（如"21-23"）
		if strings.Contains(ps, "-") {
			rangeParts := strings.Split(ps, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("端口范围格式错误，应为'起始端口-结束端口': %s", ps)
			}

			startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("端口范围起始端口格式错误: %s", rangeParts[0])
			}

			endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("端口范围结束端口格式错误: %s", rangeParts[1])
			}

			if startPort < 1 || startPort > 65535 {
				return nil, fmt.Errorf("端口范围起始端口超出有效范围（1-65535）: %d", startPort)
			}
			if endPort < 1 || endPort > 65535 {
				return nil, fmt.Errorf("端口范围结束端口超出有效范围（1-65535）: %d", endPort)
			}
			if startPort > endPort {
				return nil, fmt.Errorf("端口范围起始端口不能大于结束端口: %d-%d", startPort, endPort)
			}

			// 添加范围内的所有端口
			for port := startPort; port <= endPort; port++ {
				ports = append(ports, port)
			}
		} else {
			// 单个端口号
			port, err := strconv.Atoi(ps)
			if err != nil {
				return nil, fmt.Errorf("端口格式错误: %s", ps)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口超出有效范围（1-65535）: %d", port)
			}
			ports = append(ports, port)
		}
	}

	// 验证延迟类型
	delayType := DelayType(*delayTypeFlag)
	validDelayTypes := []DelayType{ConstantDelay, RandomDelay, Function1, Function2, Function3, Function4}
	valid := false
	for _, vt := range validDelayTypes {
		if delayType == vt {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("无效的延迟类型，支持：constant/random/function1/function2/function3/function4")
	}

	// 验证延迟值
	if *delayValFlag <= 0 {
		return nil, fmt.Errorf("延迟基础值必须大于0")
	}

	// 返回参数
	return &ScanParams{
		Targets:    targets,
		Ports:      ports,
		DelayType:  delayType,
		DelayValue: *delayValFlag,
		Timeout:    *timeoutFlag,
		EnableUDP:  *enableUDPFlag,
		Format:     *formatFlag,
	}, nil
}

// parseIPRange 解析IP范围格式如"192.168.1.1-254"
func parseIPRange(ipRange string) ([]string, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format")
	}

	baseIP := parts[0]
	lastOctetRange := parts[1]

	ipParts := strings.Split(baseIP, ".")
	if len(ipParts) != 4 {
		return nil, fmt.Errorf("invalid IP address")
	}

	start, err := strconv.Atoi(ipParts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid last octet")
	}

	end, err := strconv.Atoi(lastOctetRange)
	if err != nil {
		return nil, fmt.Errorf("invalid range end")
	}

	// 验证范围合理性
	if start < 0 || start > 255 || end < 0 || end > 255 {
		return nil, fmt.Errorf("IP地址范围超出有效范围（0-255）")
	}
	if start > end {
		return nil, fmt.Errorf("起始地址不能大于结束地址")
	}
	if end-start > 1000 {
		return nil, fmt.Errorf("IP范围过大，最大支持1000个地址")
	}

	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", ipParts[0], ipParts[1], ipParts[2], i))
	}
	return ips, nil
}

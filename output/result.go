package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time" // 添加time包导入

	"example.com/project/scanner"
)

// Result 扫描结果汇总
type Result struct {
	ScanTime        string                                         // 扫描时间
	AliveHosts      []string                                       // 在线主机
	OpenPorts       map[string][]int                               // 开放端口
	OSInfo          map[string]string                              // 操作系统信息
	ServiceInfo     map[string]map[int]*scanner.ServiceFingerprint // 服务指纹信息（增强）
	UDPInfo         interface{}                                    // UDP扫描结果
	Vulnerabilities map[string]*scanner.VulnerabilityScanResult    // 漏洞扫描结果
}

// NewResult 创建新的Result实例
func NewResult(aliveHosts []string, openPorts map[string][]int, osInfo map[string]string, serviceInfo map[string]map[int]*scanner.ServiceFingerprint) *Result {
	return &Result{
		ScanTime:    time.Now().Format("2006-01-02 15:04:05"),
		AliveHosts:  aliveHosts,
		OpenPorts:   openPorts,
		OSInfo:      osInfo,
		ServiceInfo: serviceInfo,
		UDPInfo:     nil, // 初始化为nil，后续可通过SetUDPInfo设置
	}
}

// SetUDPInfo 设置UDP扫描结果
func (r *Result) SetUDPInfo(udpInfo interface{}) {
	r.UDPInfo = udpInfo
}

// SetVulnerabilities 设置漏洞扫描结果
func (r *Result) SetVulnerabilities(vulns map[string]*scanner.VulnerabilityScanResult) {
	r.Vulnerabilities = vulns
}

// Print 控制台打印结果（统一简化版）
func (r *Result) Print() {
	fmt.Println("==================== 扫描结果汇总 ====================")
	fmt.Printf("扫描时间: %s\n", r.ScanTime)
	fmt.Printf("在线主机数量: %d\n", len(r.AliveHosts))

	fmt.Println("\n--- 主机详情 ---")
	for _, host := range r.AliveHosts {
		fmt.Printf("\n主机: %s\n", host)
		fmt.Printf("  操作系统: %s\n", r.OSInfo[host])

		// 整合TCP和UDP端口信息
		fmt.Printf("  开放端口:\n")

		// 显示TCP端口
		if tcpPorts, exists := r.OpenPorts[host]; exists && len(tcpPorts) > 0 {
			fmt.Printf("    TCP: %v\n", tcpPorts)
		}

		// 显示UDP端口（如果存在且确认开放）
		if r.UDPInfo != nil {
			if udpInfo, ok := r.UDPInfo.(map[string]map[string]interface{}); ok {
				if hostUDPInfo, exists := udpInfo[host]; exists {
					// 只显示确认开放的UDP端口（有响应数据）
					confirmedUDPPorts := []int{}
					for portKey, portInfo := range hostUDPInfo {
						// 检查端口是否确认开放（有响应数据）
						if info, ok := portInfo.(map[string]interface{}); ok {
							if status, exists := info["status"]; exists && status == "open" {
								if banner, exists := info["banner"]; exists && banner != "" {
									// 过滤掉"无响应（端口可能开放）"的端口
									if banner != "无响应（端口可能开放）" {
										// 尝试解析端口号（移除"port_"前缀）
										if port, err := strconv.Atoi(strings.TrimPrefix(portKey, "port_")); err == nil {
											confirmedUDPPorts = append(confirmedUDPPorts, port)
										}
									}
								}
							}
						}
					}

					if len(confirmedUDPPorts) > 0 {
						fmt.Printf("    UDP: %v\n", confirmedUDPPorts)
					}
				}
			}
		}

		// 显示服务信息（包含必要的指纹详情）
		fmt.Printf("  服务信息:\n")
		if services, exists := r.ServiceInfo[host]; exists && len(services) > 0 {
			for port, fingerprint := range services {
				fmt.Printf("    端口 %d: %s", port, fingerprint.ServiceName)
				if fingerprint.ServiceVersion != "" {
					fmt.Printf(" (%s)", fingerprint.ServiceVersion)
				}
				fmt.Printf(" [%d%%]\n", fingerprint.Confidence)

				// 显示重要的指纹信息（解决乱码问题）
				if fingerprint.Banner != "" && len(fingerprint.Banner) < 100 {
					// 过滤非ASCII字符，解决乱码问题
					cleanBanner := filterNonASCII(fingerprint.Banner)
					if cleanBanner != "" {
						fmt.Printf("        Banner: %s\n", cleanBanner)
					}
				}
			}
		} else {
			fmt.Printf("    无服务识别信息\n")
		}

		// 显示漏洞信息
		if vulns, exists := r.Vulnerabilities[host]; exists && len(vulns.Vulnerabilities) > 0 {
			fmt.Printf("  漏洞信息 (%d个):\n", len(vulns.Vulnerabilities))
			for i, vuln := range vulns.Vulnerabilities {
				fmt.Printf("    %d. [%s] %s [%s]\n", i+1, vuln.VulnerabilityID, vuln.Title, vuln.Severity)
				fmt.Printf("        影响服务: %s %s\n", vuln.AffectedService, vuln.AffectedVersion)
				if vuln.FixedVersion != "" {
					fmt.Printf("        修复版本: %s\n", vuln.FixedVersion)
				}
			}
		} else {
			fmt.Printf("  无漏洞发现\n")
		}
	}

	fmt.Println("=====================================================")
}

// filterNonASCII 过滤非ASCII字符，解决乱码问题
func filterNonASCII(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 { // 只保留可打印的ASCII字符
			result.WriteRune(r)
		} else if r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r) // 保留基本的控制字符
		}
		// 其他非ASCII字符被过滤掉
	}
	return result.String()
}

// SaveToFile 保存结果到文件，支持多种格式
// 格式选项: "txt", "csv", "tsv", "json"
func (r *Result) SaveToFile(filename, format string) error {
	// 默认使用txt格式
	if format == "" {
		format = "txt"
	}

	switch format {
	case "csv", "tsv":
		return r.saveAsTable(filename, format)
	case "json":
		return r.saveAsJSON(filename)
	default: // 包括 "txt"
		return r.saveAsTxt(filename)
	}
}

// saveAsTxt 保存为文本格式
func (r *Result) saveAsTxt(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString("==================== 扫描结果汇总 ====================\n")
	if err != nil { // 增加错误检查，避免后续写入无效
		return err
	}
	_, err = file.WriteString(fmt.Sprintf("扫描时间: %s\n", r.ScanTime))
	if err != nil {
		return err
	}
	_, err = file.WriteString(fmt.Sprintf("在线主机数量: %d\n", len(r.AliveHosts)))
	if err != nil {
		return err
	}

	_, err = file.WriteString("\n--- 主机详情 ---\n")
	if err != nil {
		return err
	}

	for _, host := range r.AliveHosts {
		_, err = file.WriteString(fmt.Sprintf("\n主机: %s\n", host))
		if err != nil {
			return err
		}
		_, err = file.WriteString(fmt.Sprintf("  操作系统: %s\n", r.OSInfo[host]))
		if err != nil {
			return err
		}

		// 整合TCP和UDP端口信息
		_, err = file.WriteString("  开放端口:\n")
		if err != nil {
			return err
		}

		// 显示TCP端口
		if tcpPorts, exists := r.OpenPorts[host]; exists && len(tcpPorts) > 0 {
			_, err = file.WriteString(fmt.Sprintf("    TCP: %v\n", tcpPorts))
			if err != nil {
				return err
			}
		}

		// 显示UDP端口（如果存在且确认开放）
		if r.UDPInfo != nil {
			if udpInfo, ok := r.UDPInfo.(map[string]map[string]interface{}); ok {
				if hostUDPInfo, exists := udpInfo[host]; exists {
					// 只显示确认开放的UDP端口（有响应数据）
					confirmedUDPPorts := []int{}
					for portKey, portInfo := range hostUDPInfo {
						// 检查端口是否确认开放（有响应数据）
						if info, ok := portInfo.(map[string]interface{}); ok {
							if status, exists := info["status"]; exists && status == "open" {
								if banner, exists := info["banner"]; exists && banner != "" {
									// 过滤掉"无响应（端口可能开放）"的端口
									if banner != "无响应（端口可能开放）" {
										// 尝试解析端口号（移除"port_"前缀）
										if port, err := strconv.Atoi(strings.TrimPrefix(portKey, "port_")); err == nil {
											confirmedUDPPorts = append(confirmedUDPPorts, port)
										}
									}
								}
							}
						}
					}

					if len(confirmedUDPPorts) > 0 {
						_, err = file.WriteString(fmt.Sprintf("    UDP: %v\n", confirmedUDPPorts))
						if err != nil {
							return err
						}
					}
				}
			}
		}

		// 显示服务信息（包含必要的指纹详情）
		_, err = file.WriteString("  服务信息:\n")
		if err != nil {
			return err
		}
		if services, exists := r.ServiceInfo[host]; exists && len(services) > 0 {
			for port, fingerprint := range services {
				_, err = file.WriteString(fmt.Sprintf("    端口 %d: %s", port, fingerprint.ServiceName))
				if err != nil {
					return err
				}
				if fingerprint.ServiceVersion != "" {
					_, err = file.WriteString(fmt.Sprintf(" (%s)", fingerprint.ServiceVersion))
					if err != nil {
						return err
					}
				}
				_, err = file.WriteString(fmt.Sprintf(" [%d%%]\n", fingerprint.Confidence))
				if err != nil {
					return err
				}

				// 保存重要的指纹信息（解决乱码问题）
				if fingerprint.Banner != "" && len(fingerprint.Banner) < 100 {
					// 过滤非ASCII字符，解决乱码问题
					cleanBanner := filterNonASCII(fingerprint.Banner)
					if cleanBanner != "" {
						_, err = file.WriteString(fmt.Sprintf("        Banner: %s\n", cleanBanner))
						if err != nil {
							return err
						}
					}
				}
			}
		} else {
			_, err = file.WriteString("    无服务识别信息\n")
			if err != nil {
				return err
			}
		}

		// 保存漏洞信息
		if vulns, exists := r.Vulnerabilities[host]; exists && len(vulns.Vulnerabilities) > 0 {
			_, err = file.WriteString(fmt.Sprintf("  漏洞信息 (%d个):\n", len(vulns.Vulnerabilities)))
			if err != nil {
				return err
			}
			for i, vuln := range vulns.Vulnerabilities {
				_, err = file.WriteString(fmt.Sprintf("    %d. [%s] %s [%s]\n", i+1, vuln.VulnerabilityID, vuln.Title, vuln.Severity))
				if err != nil {
					return err
				}
				_, err = file.WriteString(fmt.Sprintf("        影响服务: %s %s\n", vuln.AffectedService, vuln.AffectedVersion))
				if err != nil {
					return err
				}
				if vuln.FixedVersion != "" {
					_, err = file.WriteString(fmt.Sprintf("        修复版本: %s\n", vuln.FixedVersion))
					if err != nil {
						return err
					}
				}
			}
		} else {
			_, err = file.WriteString("  无漏洞发现\n")
			if err != nil {
				return err
			}
		}
	}

	// 循环结束后写入结尾分隔符（此时语句在函数体中，非孤立）
	_, err = file.WriteString("=====================================================\n")
	if err != nil {
		return err
	}

	return nil // 最终返回nil表示无错误
}

// saveAsTable 保存为表格格式 (CSV/TSV)
func (r *Result) saveAsTable(filename, format string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 确定分隔符
	delimiter := ","
	if format == "tsv" {
		delimiter = "\t"
	}

	// 写入表头
	header := []string{
		"主机", "操作系统", "端口", "协议", "服务名称",
		"服务版本", "置信度", "漏洞数量", "扫描时间",
	}
	file.WriteString(strings.Join(header, delimiter) + "\n")

	// 写入数据行
	for _, host := range r.AliveHosts {
		// TCP端口
		if tcpPorts, exists := r.OpenPorts[host]; exists {
			for _, port := range tcpPorts {
				fingerprint := r.ServiceInfo[host][port]
				vulnCount := 0
				if vulns, exists := r.Vulnerabilities[host]; exists {
					vulnCount = len(vulns.Vulnerabilities)
				}

				row := []string{
					host,
					r.OSInfo[host],
					strconv.Itoa(port),
					"TCP",
					fingerprint.ServiceName,
					fingerprint.ServiceVersion,
					strconv.Itoa(fingerprint.Confidence),
					strconv.Itoa(vulnCount),
					r.ScanTime,
				}
				file.WriteString(strings.Join(row, delimiter) + "\n")
			}
		}

		// UDP端口
		if r.UDPInfo != nil {
			if udpInfo, ok := r.UDPInfo.(map[string]map[string]interface{}); ok {
				if hostUDPInfo, exists := udpInfo[host]; exists {
					for portKey, portInfo := range hostUDPInfo {
						if info, ok := portInfo.(map[string]interface{}); ok {
							if status, exists := info["status"]; exists && status == "open" {
								if banner, exists := info["banner"]; exists && banner != "" && banner != "无响应（端口可能开放）" {
									if port, err := strconv.Atoi(strings.TrimPrefix(portKey, "port_")); err == nil {
										row := []string{
											host,
											r.OSInfo[host],
											strconv.Itoa(port),
											"UDP",
											"",  // 服务名称
											"",  // 服务版本
											"",  // 置信度
											"0", // 漏洞数量
											r.ScanTime,
										}
										file.WriteString(strings.Join(row, delimiter) + "\n")
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// saveAsJSON 保存为JSON格式
func (r *Result) saveAsJSON(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 创建可序列化的结构
	type HostResult struct {
		Host            string                              `json:"host"`
		OS              string                              `json:"os"`
		TCPPorts        []int                               `json:"tcp_ports,omitempty"`
		UDPPorts        []int                               `json:"udp_ports,omitempty"`
		Services        map[int]*scanner.ServiceFingerprint `json:"services,omitempty"`
		Vulnerabilities []*scanner.DetectedVulnerability    `json:"vulnerabilities,omitempty"`
	}

	type JSONResult struct {
		ScanTime   string       `json:"scan_time"`
		AliveHosts []HostResult `json:"alive_hosts"`
	}

	result := JSONResult{
		ScanTime: r.ScanTime,
	}

	for _, host := range r.AliveHosts {
		hostResult := HostResult{
			Host:     host,
			OS:       r.OSInfo[host],
			Services: r.ServiceInfo[host],
		}

		// TCP端口
		if ports, exists := r.OpenPorts[host]; exists {
			hostResult.TCPPorts = ports
		}

		// UDP端口
		if r.UDPInfo != nil {
			if udpInfo, ok := r.UDPInfo.(map[string]map[string]interface{}); ok {
				if hostUDPInfo, exists := udpInfo[host]; exists {
					udpPorts := []int{}
					for portKey, portInfo := range hostUDPInfo {
						if info, ok := portInfo.(map[string]interface{}); ok {
							if status, exists := info["status"]; exists && status == "open" {
								if banner, exists := info["banner"]; exists && banner != "" && banner != "无响应（端口可能开放）" {
									if port, err := strconv.Atoi(strings.TrimPrefix(portKey, "port_")); err == nil {
										udpPorts = append(udpPorts, port)
									}
								}
							}
						}
					}
					hostResult.UDPPorts = udpPorts
				}
			}
		}

		// 漏洞信息
		if vulns, exists := r.Vulnerabilities[host]; exists {
			// 将值切片转换为指针切片
			ptrVulns := make([]*scanner.DetectedVulnerability, len(vulns.Vulnerabilities))
			for i := range vulns.Vulnerabilities {
				ptrVulns[i] = &vulns.Vulnerabilities[i]
			}
			hostResult.Vulnerabilities = ptrVulns
		}

		result.AliveHosts = append(result.AliveHosts, hostResult)
	}

	// 编码为JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

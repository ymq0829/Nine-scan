package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

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

		// 显示开放端口
		fmt.Printf("  开放端口:\n")

		// 显示TCP端口 - 修复显示逻辑
		if tcpPorts, exists := r.OpenPorts[host]; exists && len(tcpPorts) > 0 {
			fmt.Printf("    TCP: %v\n", tcpPorts)
		} else {
			fmt.Printf("    TCP: 无开放端口\n")
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
					} else {
						fmt.Printf("    UDP: 无开放端口\n")
					}
				} else {
					fmt.Printf("    UDP: 无开放端口\n")
				}
			} else {
				fmt.Printf("    UDP: 无扫描数据\n")
			}
		} else {
			fmt.Printf("    UDP: 未启用扫描\n")
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
// 格式: "txt", "csv", "tsv", "json"
func (r *Result) SaveToFile(filename, format string) error {
	log.Printf("保存文件: %s, 格式: %s", filename, format)

	// 默认使用txt格式
	if format == "" {
		format = "txt"
	}

	// 统一转换为小写进行比较
	format = strings.ToLower(format)

	switch format {
	case "csv":
		return r.SaveToCSV(filename)
	case "tsv":
		return r.SaveToTSV(filename)
	case "json":
		return r.saveAsJSON(filename)
	default: // 包括 "txt"
		return r.saveAsTxt(filename)
	}
}

// SaveAuto 自动保存结果，默认保存为TXT格式
func (r *Result) SaveAuto() error {
	// 生成默认文件名：scan_result_时间戳.txt
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("scan_result_%s.txt", timestamp)

	log.Printf("自动保存结果到: %s", filename)
	return r.saveAsTxt(filename)
}

// SaveWithOptions 保存结果并提供格式选项
func (r *Result) SaveWithOptions() error {
	// 首先自动保存为TXT格式
	if err := r.SaveAuto(); err != nil {
		return fmt.Errorf("自动保存失败: %v", err)
	}

	fmt.Println("扫描结果已自动保存为TXT格式")
	fmt.Println("如果需要其他格式，请使用以下命令:")
	fmt.Println("  - 保存为CSV格式: project.exe -format csv")
	fmt.Println("  - 保存为TSV格式: project.exe -format tsv")
	fmt.Println("  - 保存为JSON格式: project.exe -format json")

	return nil
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

		// 显示TCP端口 - 修复显示逻辑
		if tcpPorts, exists := r.OpenPorts[host]; exists && len(tcpPorts) > 0 {
			_, err = file.WriteString(fmt.Sprintf("    TCP: %v\n", tcpPorts))
			if err != nil {
				return err
			}
		} else {
			_, err = file.WriteString("    TCP: 无开放端口\n")
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
					} else {
						_, err = file.WriteString("    UDP: 无开放端口\n")
						if err != nil {
							return err
						}
					}
				} else {
					_, err = file.WriteString("    UDP: 无开放端口\n")
					if err != nil {
						return err
					}
				}
			} else {
				_, err = file.WriteString("    UDP: 无扫描数据\n")
				if err != nil {
					return err
				}
			}
		} else {
			_, err = file.WriteString("    UDP: 未启用扫描\n")
			if err != nil {
				return err
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

// SaveToCSV 保存为CSV格式
func (r *Result) SaveToCSV(filename string) error {
	return r.saveAsDelimitedFile(filename, ",")
}

// SaveToTSV 保存为TSV格式
func (r *Result) SaveToTSV(filename string) error {
	return r.saveAsDelimitedFile(filename, "\t")
}

// saveAsDelimitedFile 保存为分隔符格式文件
func (r *Result) saveAsDelimitedFile(filename, delimiter string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 写入UTF-8 BOM，解决Windows下的乱码问题
	if _, err := file.WriteString("\xEF\xBB\xBF"); err != nil {
		return err
	}

	writer := csv.NewWriter(file)
	writer.Comma = rune(delimiter[0]) // 设置分隔符
	defer writer.Flush()

	// 写入扫描基本信息
	if err := writer.Write([]string{"扫描信息", "", "", "", "", ""}); err != nil {
		return err
	}
	if err := writer.Write([]string{"扫描时间", r.ScanTime, "", "", "", ""}); err != nil {
		return err
	}
	if err := writer.Write([]string{"在线主机数量", fmt.Sprintf("%d", len(r.AliveHosts)), "", "", "", ""}); err != nil {
		return err
	}
	if err := writer.Write([]string{"", "", "", "", "", ""}); err != nil {
		return err
	}

	// 写入主机详情表头
	header := []string{
		"主机", "操作系统", "端口", "协议", "服务名称",
		"服务版本", "置信度", "漏洞数量", "扫描时间",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// 写入数据行
	for _, host := range r.AliveHosts {
		// 获取操作系统信息，如果不存在则使用默认值
		osInfo := r.OSInfo[host]
		if osInfo == "" {
			osInfo = "Unknown"
		}

		// 检查是否有TCP端口信息
		if tcpPorts, exists := r.OpenPorts[host]; exists && len(tcpPorts) > 0 {
			for _, port := range tcpPorts {
				// 获取服务指纹信息
				var fingerprint *scanner.ServiceFingerprint
				if services, exists := r.ServiceInfo[host]; exists {
					fingerprint = services[port]
				}

				// 计算漏洞数量
				vulnCount := 0
				if vulns, exists := r.Vulnerabilities[host]; exists {
					vulnCount = len(vulns.Vulnerabilities)
				}

				// 准备服务信息
				serviceName := ""
				serviceVersion := ""
				confidence := "0"
				if fingerprint != nil {
					serviceName = fingerprint.ServiceName
					if serviceName == "" {
						serviceName = "Unknown"
					}
					serviceVersion = fingerprint.ServiceVersion
					confidence = strconv.Itoa(fingerprint.Confidence)
				}

				// 写入TCP端口行
				row := []string{
					host,
					osInfo,
					strconv.Itoa(port),
					"TCP",
					serviceName,
					serviceVersion,
					confidence,
					strconv.Itoa(vulnCount),
					r.ScanTime,
				}
				if err := writer.Write(row); err != nil {
					return err
				}
			}
		} else {
			// 如果没有TCP端口信息，至少写入主机基本信息
			row := []string{
				host,
				osInfo,
				"",  // 端口
				"",  // 协议
				"",  // 服务名称
				"",  // 服务版本
				"",  // 置信度
				"0", // 漏洞数量
				r.ScanTime,
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}

		// UDP端口（如果有）
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
											osInfo,
											strconv.Itoa(port),
											"UDP",
											"",  // 服务名称
											"",  // 服务版本
											"",  // 置信度
											"0", // 漏洞数量
											r.ScanTime,
										}
										if err := writer.Write(row); err != nil {
											return err
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 如果没有写入任何数据行，写入一条空行表示没有数据
	if len(r.AliveHosts) == 0 {
		row := []string{
			"无存活主机",
			"", "", "", "", "", "", "", "",
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// JSONResult JSON序列化结构
type JSONResult struct {
	ScanTime   string       `json:"scan_time"`
	TotalHosts int          `json:"total_hosts"`
	AliveHosts []HostResult `json:"alive_hosts"`
}

// HostResult 主机结果结构
type HostResult struct {
	Host            string                              `json:"host,omitempty"`
	OS              string                              `json:"os,omitempty"`
	TCPPorts        []int                               `json:"tcp_ports,omitempty"`
	UDPPorts        []int                               `json:"udp_ports,omitempty"`
	Services        map[int]*scanner.ServiceFingerprint `json:"services,omitempty"`
	Vulnerabilities []scanner.DetectedVulnerability     `json:"vulnerabilities,omitempty"`
}

// saveAsJSON 保存为JSON格式
func (r *Result) saveAsJSON(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	result := JSONResult{
		ScanTime:   r.ScanTime,
		TotalHosts: len(r.AliveHosts),
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

		// 漏洞信息 - 直接使用值切片
		if vulns, exists := r.Vulnerabilities[host]; exists && len(vulns.Vulnerabilities) > 0 {
			hostResult.Vulnerabilities = vulns.Vulnerabilities
		}

		result.AliveHosts = append(result.AliveHosts, hostResult)
	}

	// 编码为JSON，使用更友好的缩进
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(result)
}

// LoadFromFile 从文件加载结果（支持多种格式）
func (r *Result) LoadFromFile(filename string) error {
	// 根据文件扩展名确定格式
	ext := strings.ToLower(filename[strings.LastIndex(filename, ".")+1:])

	switch ext {
	case "json":
		return r.loadFromJSON(filename)
	case "csv", "tsv":
		return r.loadFromCSV(filename)
	default:
		return fmt.Errorf("不支持的文件格式: %s", ext)
	}
}

// loadFromJSON 从JSON文件加载结果
func (r *Result) loadFromJSON(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var result JSONResult
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&result); err != nil {
		return err
	}

	// 将加载的数据设置到当前Result实例中
	r.ScanTime = result.ScanTime

	// 重新构建数据结构
	r.AliveHosts = make([]string, 0)
	r.OpenPorts = make(map[string][]int)
	r.OSInfo = make(map[string]string)
	r.ServiceInfo = make(map[string]map[int]*scanner.ServiceFingerprint)
	r.Vulnerabilities = make(map[string]*scanner.VulnerabilityScanResult)

	for _, hostResult := range result.AliveHosts {
		r.AliveHosts = append(r.AliveHosts, hostResult.Host)
		r.OSInfo[hostResult.Host] = hostResult.OS
		r.OpenPorts[hostResult.Host] = hostResult.TCPPorts
		r.ServiceInfo[hostResult.Host] = hostResult.Services

		if len(hostResult.Vulnerabilities) > 0 {
			r.Vulnerabilities[hostResult.Host] = &scanner.VulnerabilityScanResult{
				Host:            hostResult.Host,
				OS:              hostResult.OS,
				OpenPorts:       hostResult.TCPPorts,
				Vulnerabilities: hostResult.Vulnerabilities,
				ScanTimestamp:   time.Now(),
			}
		}
	}

	return nil
}

// loadFromCSV 从CSV/TSV文件加载结果
func (r *Result) loadFromCSV(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 检测分隔符
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // 允许字段数量可变

	// 读取所有行
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	// 重新初始化数据结构
	r.AliveHosts = make([]string, 0)
	r.OpenPorts = make(map[string][]int)
	r.OSInfo = make(map[string]string)
	r.ServiceInfo = make(map[string]map[int]*scanner.ServiceFingerprint)
	r.Vulnerabilities = make(map[string]*scanner.VulnerabilityScanResult)

	// 跳过表头，从数据行开始处理
	for i := 1; i < len(records); i++ {
		if len(records[i]) < 9 {
			continue // 跳过不完整的行
		}

		host := records[i][0]
		os := records[i][1]
		portStr := records[i][2]
		protocol := records[i][3]
		serviceName := records[i][4]
		serviceVersion := records[i][5]
		confidenceStr := records[i][6]
		vulnCountStr := records[i][7]
		scanTime := records[i][8]

		// 设置扫描时间
		if r.ScanTime == "" {
			r.ScanTime = scanTime
		}

		// 添加主机到存活列表
		if !contains(r.AliveHosts, host) {
			r.AliveHosts = append(r.AliveHosts, host)
		}

		// 设置操作系统信息
		r.OSInfo[host] = os

		// 处理端口信息
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// 添加到开放端口列表
		if protocol == "TCP" {
			if _, exists := r.OpenPorts[host]; !exists {
				r.OpenPorts[host] = make([]int, 0)
			}
			if !containsInt(r.OpenPorts[host], port) {
				r.OpenPorts[host] = append(r.OpenPorts[host], port)
			}
		}

		// 处理服务信息
		if serviceName != "" {
			if _, exists := r.ServiceInfo[host]; !exists {
				r.ServiceInfo[host] = make(map[int]*scanner.ServiceFingerprint)
			}

			confidence, _ := strconv.Atoi(confidenceStr)
			r.ServiceInfo[host][port] = &scanner.ServiceFingerprint{
				ServiceName:    serviceName,
				ServiceVersion: serviceVersion,
				Confidence:     confidence,
				Protocol:       protocol,
				Port:           port,
			}
		}

		// 处理漏洞信息（简化处理）
		vulnCount, _ := strconv.Atoi(vulnCountStr)
		if vulnCount > 0 {
			if _, exists := r.Vulnerabilities[host]; !exists {
				r.Vulnerabilities[host] = &scanner.VulnerabilityScanResult{
					Host:            host,
					OS:              os,
					OpenPorts:       r.OpenPorts[host],
					Vulnerabilities: make([]scanner.DetectedVulnerability, 0),
					ScanTimestamp:   time.Now(),
				}
			}
		}
	}

	return nil
}

// 辅助函数：检查字符串切片是否包含某个元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// 辅助函数：检查整数切片是否包含某个元素
func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

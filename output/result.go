package output

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time" // 添加time包导入

	"example.com/project/scanner"
)

// Result 扫描结果汇总
type Result struct {
	ScanTime    string                                         // 扫描时间
	AliveHosts  []string                                       // 在线主机
	OpenPorts   map[string][]int                               // 开放端口
	OSInfo      map[string]string                              // 操作系统信息
	ServiceInfo map[string]map[int]*scanner.ServiceFingerprint // 服务指纹信息（增强）
	UDPInfo     interface{}                                    // UDP扫描结果
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

// SaveToFile 保存结果到文件（统一简化版）
func (r *Result) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString("==================== 扫描结果汇总 ====================\n")
	_, err = file.WriteString(fmt.Sprintf("扫描时间: %s\n", r.ScanTime))
	_, err = file.WriteString(fmt.Sprintf("在线主机数量: %d\n", len(r.AliveHosts)))

	_, err = file.WriteString("\n--- 主机详情 ---\n")

	for _, host := range r.AliveHosts {
		_, err = file.WriteString(fmt.Sprintf("\n主机: %s\n", host))
		_, err = file.WriteString(fmt.Sprintf("  操作系统: %s\n", r.OSInfo[host]))

		// 整合TCP和UDP端口信息
		_, err = file.WriteString("  开放端口:\n")

		// 显示TCP端口
		if tcpPorts, exists := r.OpenPorts[host]; exists && len(tcpPorts) > 0 {
			_, err = file.WriteString(fmt.Sprintf("    TCP: %v\n", tcpPorts))
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
					}
				}
			}
		}

		_, err = file.WriteString("  服务信息:\n")
		for port, fingerprint := range r.ServiceInfo[host] {
			_, err = file.WriteString(fmt.Sprintf("    端口 %d: %s", port, fingerprint.ServiceName))
			if fingerprint.ServiceVersion != "" {
				_, err = file.WriteString(fmt.Sprintf(" (%s)", fingerprint.ServiceVersion))
			}
			_, err = file.WriteString(fmt.Sprintf(" [%d%%]\n", fingerprint.Confidence))

			// 保存重要的指纹信息（解决乱码问题）
			if fingerprint.Banner != "" && len(fingerprint.Banner) < 100 {
				// 过滤非ASCII字符，解决乱码问题
				cleanBanner := filterNonASCII(fingerprint.Banner)
				if cleanBanner != "" {
					_, err = file.WriteString(fmt.Sprintf("        Banner: %s\n", cleanBanner))
				}
			}
		}
	}

	_, err = file.WriteString("=====================================================\n")

	return err
}

// 删除统计信息相关方法
// GetServiceStatistics 方法已删除
// PrintStatistics 方法已删除
// GetConfidenceSummary 方法已删除
// PrintConfidenceSummary 方法已删除

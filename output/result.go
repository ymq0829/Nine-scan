package output

import (
	"fmt"
	"os"
	"time"

	"example.com/project/scanner"
)

// Result 扫描结果汇总
type Result struct {
	ScanTime    string                                         // 扫描时间
	AliveHosts  []string                                       // 在线主机
	OpenPorts   map[string][]int                               // 开放端口
	OSInfo      map[string]string                              // 操作系统信息
	ServiceInfo map[string]map[int]*scanner.ServiceFingerprint // 服务指纹信息（增强）
	SMBUDPInfo  interface{}                                    // SMB/UDP扫描结果
}

// NewResult 初始化结果（新增serviceInfo参数）
func NewResult(alive []string, ports map[string][]int, osInfo map[string]string, serviceInfo map[string]map[int]*scanner.ServiceFingerprint) *Result {
	return &Result{
		ScanTime:    time.Now().Format("2006-01-02 15:04:05"),
		AliveHosts:  alive,
		OpenPorts:   ports,
		OSInfo:      osInfo,
		ServiceInfo: serviceInfo, // 赋值服务指纹信息
	}
}

// SetSMBUDPInfo 设置SMB/UDP扫描结果
func (r *Result) SetSMBUDPInfo(smbUDPInfo interface{}) {
	r.SMBUDPInfo = smbUDPInfo
}

// Print 控制台打印结果
func (r *Result) Print() {
	fmt.Println("==================== 扫描结果汇总 ====================")
	fmt.Printf("扫描时间: %s\n", r.ScanTime)
	fmt.Printf("在线主机数量: %d\n", len(r.AliveHosts))

	// 显示SMB/UDP扫描状态
	if r.SMBUDPInfo != nil {
		fmt.Println("\n--- SMB/UDP扫描状态 ---")
		if smbUDPResults, ok := r.SMBUDPInfo.(map[string]interface{}); ok {
			for host, results := range smbUDPResults {
				fmt.Printf("主机 %s:\n", host)
				if hostResults, ok := results.(map[string]interface{}); ok {
					for protocol, result := range hostResults {
						fmt.Printf("  %s: %v\n", protocol, result)
					}
				}
			}
		}
	}

	fmt.Println("\n--- 主机详情 ---")
	for _, host := range r.AliveHosts {
		fmt.Printf("\n主机: %s\n", host)
		fmt.Printf("  操作系统: %s\n", r.OSInfo[host])
		fmt.Printf("  开放端口: %v\n", r.OpenPorts[host])
		fmt.Printf("  服务指纹信息:\n")
		for port, fingerprint := range r.ServiceInfo[host] {
			fmt.Printf("    端口 %d:\n", port)
			fmt.Printf("      服务名称: %s\n", fingerprint.ServiceName)
			if fingerprint.ServiceVersion != "" {
				fmt.Printf("      版本信息: %s\n", fingerprint.ServiceVersion)
			}
			fmt.Printf("      协议类型: %s\n", fingerprint.Protocol)
			fmt.Printf("      识别置信度: %d%%\n", fingerprint.Confidence)
			if fingerprint.Banner != "" {
				fmt.Printf("      原始Banner: %s\n", fingerprint.Banner)
			}
			if fingerprint.Fingerprint != "" {
				fmt.Printf("      指纹特征: %s\n", fingerprint.Fingerprint)
			}
		}
	}
	fmt.Println("=====================================================")
}

// SaveToFile 保存结果到文件
func (r *Result) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString("==================== 扫描结果汇总 ====================\n")
	_, err = file.WriteString(fmt.Sprintf("扫描时间: %s\n", r.ScanTime))
	_, err = file.WriteString(fmt.Sprintf("在线主机数量: %d\n", len(r.AliveHosts)))

	// 保存SMB/UDP扫描状态
	if r.SMBUDPInfo != nil {
		_, err = file.WriteString("\n--- SMB/UDP扫描状态 ---\n")
		if smbUDPResults, ok := r.SMBUDPInfo.(map[string]interface{}); ok {
			for host, results := range smbUDPResults {
				_, err = file.WriteString(fmt.Sprintf("主机 %s:\n", host))
				if hostResults, ok := results.(map[string]interface{}); ok {
					for protocol, result := range hostResults {
						_, err = file.WriteString(fmt.Sprintf("  %s: %v\n", protocol, result))
					}
				}
			}
		}
	}

	_, err = file.WriteString("\n--- 主机详情 ---\n")

	for _, host := range r.AliveHosts {
		_, err = file.WriteString(fmt.Sprintf("\n主机: %s\n", host))
		_, err = file.WriteString(fmt.Sprintf("  操作系统: %s\n", r.OSInfo[host]))
		_, err = file.WriteString(fmt.Sprintf("  开放端口: %v\n", r.OpenPorts[host]))
		_, err = file.WriteString("  服务指纹信息:\n")
		for port, fingerprint := range r.ServiceInfo[host] {
			_, err = file.WriteString(fmt.Sprintf("    端口 %d:\n", port))
			_, err = file.WriteString(fmt.Sprintf("      服务名称: %s\n", fingerprint.ServiceName))
			if fingerprint.ServiceVersion != "" {
				_, err = file.WriteString(fmt.Sprintf("      版本信息: %s\n", fingerprint.ServiceVersion))
			}
			_, err = file.WriteString(fmt.Sprintf("      协议类型: %s\n", fingerprint.Protocol))
			_, err = file.WriteString(fmt.Sprintf("      识别置信度: %d%%\n", fingerprint.Confidence))
			if fingerprint.Banner != "" {
				_, err = file.WriteString(fmt.Sprintf("      原始Banner: %s\n", fingerprint.Banner))
			}
			if fingerprint.Fingerprint != "" {
				_, err = file.WriteString(fmt.Sprintf("      指纹特征: %s\n", fingerprint.Fingerprint))
			}
		}
	}
	_, err = file.WriteString("=====================================================\n")

	return err
}

// PrintEnhanced 增强版结果输出，显示更详细的指纹信息
func (r *Result) PrintEnhanced() {
	fmt.Println("==================== 增强扫描结果 ====================")
	fmt.Printf("扫描时间: %s\n", r.ScanTime)
	fmt.Printf("在线主机数量: %d\n", len(r.AliveHosts))

	fmt.Println("\n--- 详细服务指纹信息 ---")
	for _, host := range r.AliveHosts {
		fmt.Printf("\n主机: %s\n", host)
		fmt.Printf("  操作系统: %s\n", r.OSInfo[host])
		fmt.Printf("  开放端口数: %d\n", len(r.OpenPorts[host]))

		for port, fingerprint := range r.ServiceInfo[host] {
			fmt.Printf("\n  端口 %d 服务指纹:\n", port)
			fmt.Printf("    ├─ 服务名称: %s\n", fingerprint.ServiceName)
			if fingerprint.ServiceVersion != "" {
				fmt.Printf("    ├─ 版本信息: %s\n", fingerprint.ServiceVersion)
			}
			fmt.Printf("    ├─ 协议类型: %s\n", fingerprint.Protocol)
			fmt.Printf("    ├─ 识别置信度: %d%%\n", fingerprint.Confidence)
			if fingerprint.Fingerprint != "" {
				fmt.Printf("    ├─ 指纹特征: %s\n", fingerprint.Fingerprint)
			}
			if fingerprint.Banner != "" {
				fmt.Printf("    ├─ 原始Banner: %s\n", fingerprint.Banner)
			}
			if len(fingerprint.Metadata) > 0 {
				fmt.Printf("    └─ 额外元数据:\n")
				for key, value := range fingerprint.Metadata {
					fmt.Printf("        %s: %s\n", key, value)
				}
			} else {
				fmt.Printf("    └─ 无额外元数据\n")
			}
		}
	}
	fmt.Println("=====================================================")
}

// SaveEnhancedToFile 保存增强版结果到文件
func (r *Result) SaveEnhancedToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString("==================== 增强扫描结果 ====================\n")
	_, err = file.WriteString(fmt.Sprintf("扫描时间: %s\n", r.ScanTime))
	_, err = file.WriteString(fmt.Sprintf("在线主机数量: %d\n", len(r.AliveHosts)))

	_, err = file.WriteString("\n--- 详细服务指纹信息 ---\n")
	for _, host := range r.AliveHosts {
		_, err = file.WriteString(fmt.Sprintf("\n主机: %s\n", host))
		_, err = file.WriteString(fmt.Sprintf("  操作系统: %s\n", r.OSInfo[host]))
		_, err = file.WriteString(fmt.Sprintf("  开放端口数: %d\n", len(r.OpenPorts[host])))

		for port, fingerprint := range r.ServiceInfo[host] {
			_, err = file.WriteString(fmt.Sprintf("\n  端口 %d 服务指纹:\n", port))
			_, err = file.WriteString(fmt.Sprintf("    ├─ 服务名称: %s\n", fingerprint.ServiceName))
			if fingerprint.ServiceVersion != "" {
				_, err = file.WriteString(fmt.Sprintf("    ├─ 版本信息: %s\n", fingerprint.ServiceVersion))
			}
			_, err = file.WriteString(fmt.Sprintf("    ├─ 协议类型: %s\n", fingerprint.Protocol))
			_, err = file.WriteString(fmt.Sprintf("    ├─ 识别置信度: %d%%\n", fingerprint.Confidence))
			if fingerprint.Fingerprint != "" {
				_, err = file.WriteString(fmt.Sprintf("    ├─ 指纹特征: %s\n", fingerprint.Fingerprint))
			}
			if fingerprint.Banner != "" {
				_, err = file.WriteString(fmt.Sprintf("    ├─ 原始Banner: %s\n", fingerprint.Banner))
			}
			if len(fingerprint.Metadata) > 0 {
				_, err = file.WriteString(fmt.Sprintf("    └─ 额外元数据:\n"))
				for key, value := range fingerprint.Metadata {
					_, err = file.WriteString(fmt.Sprintf("        %s: %s\n", key, value))
				}
			} else {
				_, err = file.WriteString(fmt.Sprintf("    └─ 无额外元数据\n"))
			}
		}
	}
	_, err = file.WriteString("=====================================================\n")

	return err
}

// GetServiceStatistics 获取服务统计信息
func (r *Result) GetServiceStatistics() map[string]int {
	stats := make(map[string]int)

	for _, hostServices := range r.ServiceInfo {
		for _, fingerprint := range hostServices {
			if fingerprint.Confidence >= 80 { // 只统计置信度高的服务
				stats[fingerprint.ServiceName]++
			}
		}
	}

	return stats
}

// PrintStatistics 打印统计信息
func (r *Result) PrintStatistics() {
	fmt.Println("\n--- 服务统计信息 ---")
	stats := r.GetServiceStatistics()

	if len(stats) == 0 {
		fmt.Println("  未发现高置信度的服务")
		return
	}

	for service, count := range stats {
		fmt.Printf("  %s: %d 个实例\n", service, count)
	}
}

// GetConfidenceSummary 获取置信度摘要
func (r *Result) GetConfidenceSummary() map[string]int {
	summary := map[string]int{
		"高置信度(>=90%)":  0,
		"中置信度(70-89%)": 0,
		"低置信度(<70%)":   0,
	}

	for _, hostServices := range r.ServiceInfo {
		for _, fingerprint := range hostServices {
			if fingerprint.Confidence >= 90 {
				summary["高置信度(>=90%)"]++
			} else if fingerprint.Confidence >= 70 {
				summary["中置信度(70-89%)"]++
			} else {
				summary["低置信度(<70%)"]++
			}
		}
	}

	return summary
}

// PrintConfidenceSummary 打印置信度摘要
func (r *Result) PrintConfidenceSummary() {
	fmt.Println("\n--- 识别置信度摘要 ---")
	summary := r.GetConfidenceSummary()

	for level, count := range summary {
		fmt.Printf("  %s: %d 个服务\n", level, count)
	}
}

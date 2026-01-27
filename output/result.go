package output

import (
	"fmt"
	"os"
	"time"
)

// Result 扫描结果汇总
type Result struct {
	ScanTime    string                    // 扫描时间
	AliveHosts  []string                  // 在线主机
	OpenPorts   map[string][]int          // 开放端口
	OSInfo      map[string]string         // 操作系统信息
	ServiceInfo map[string]map[int]string // 服务信息（新增）
	SMBUDPInfo  interface{}               // SMB/UDP扫描结果
}

// NewResult 初始化结果（新增serviceInfo参数）
func NewResult(alive []string, ports map[string][]int, osInfo map[string]string, serviceInfo map[string]map[int]string) *Result {
	return &Result{
		ScanTime:    time.Now().Format("2006-01-02 15:04:05"),
		AliveHosts:  alive,
		OpenPorts:   ports,
		OSInfo:      osInfo,
		ServiceInfo: serviceInfo, // 赋值服务信息
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
		fmt.Printf("  服务信息:\n")
		for port, service := range r.ServiceInfo[host] {
			fmt.Printf("    端口 %d: %s\n", port, service)
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
		_, err = file.WriteString("  服务信息:\n")
		for port, service := range r.ServiceInfo[host] {
			_, err = file.WriteString(fmt.Sprintf("    端口 %d: %s\n", port, service))
		}
	}
	_, err = file.WriteString("=====================================================\n")

	return err
}

package scanner

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"example.com/project/controller"
)

// SMBUDPConfig SMB/UDP扫描配置
type SMBUDPConfig struct {
	Targets   []string
	Ports     []int
	Timeout   time.Duration
	Logger    *controller.Logger
	EnableSMB bool
	EnableUDP bool
}

// SMBUDPResult SMB/UDP扫描结果
type SMBUDPResult struct {
	Host     string
	Port     int
	Protocol string
	Status   string
	Banner   string
	Error    error
}

// SMBUDPDetector SMB/UDP探测器
type SMBUDPDetector struct {
	config           *SMBUDPConfig
	progressCallback func(current, total int)
}

// NewSMBUDPDetector 创建新的SMB/UDP探测器
func NewSMBUDPDetector(config *SMBUDPConfig) *SMBUDPDetector {
	return &SMBUDPDetector{
		config: config,
	}
}

// SetProgressCallback 设置进度回调函数
func (d *SMBUDPDetector) SetProgressCallback(callback func(current, total int)) {
	d.progressCallback = callback
}

// Scan 执行SMB/UDP扫描
func (d *SMBUDPDetector) Scan() (interface{}, error) {
	results := make(map[string]map[string]interface{})
	var mu sync.Mutex

	d.config.Logger.Log("SMB/UDP扫描开始")

	// 计算总任务数
	totalTasks := 0
	if d.config.EnableSMB {
		totalTasks += len(d.config.Targets) * 1 // SMB通常使用445端口
	}
	if d.config.EnableUDP {
		totalTasks += len(d.config.Targets) * len(d.config.Ports)
	}

	completed := 0
	var wg sync.WaitGroup

	// SMB扫描（TCP 445端口）
	if d.config.EnableSMB {
		for _, target := range d.config.Targets {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()

				result := d.scanSMB(host, 445)

				mu.Lock()
				if _, exists := results[host]; !exists {
					results[host] = make(map[string]interface{})
				}
				results[host]["smb"] = result
				mu.Unlock()

				completed++
				if d.progressCallback != nil {
					d.progressCallback(completed, totalTasks)
				}
			}(target)
		}
	}

	// UDP扫描
	if d.config.EnableUDP {
		for _, target := range d.config.Targets {
			for _, port := range d.config.Ports {
				wg.Add(1)
				go func(host string, portNum int) {
					defer wg.Done()

					result := d.scanUDP(host, portNum)

					mu.Lock()
					if _, exists := results[host]; !exists {
						results[host] = make(map[string]interface{})
					}
					results[host][fmt.Sprintf("udp_%d", portNum)] = result
					mu.Unlock()

					completed++
					if d.progressCallback != nil {
						d.progressCallback(completed, totalTasks)
					}
				}(target, port)
			}
		}
	}

	wg.Wait()
	d.config.Logger.Log("SMB/UDP扫描结束")
	return results, nil
}

// scanSMB 扫描SMB服务
func (d *SMBUDPDetector) scanSMB(host string, port int) SMBUDPResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// 尝试TCP连接
	conn, err := net.DialTimeout("tcp", addr, d.config.Timeout)
	if err != nil {
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "SMB",
			Status:   "closed",
			Error:    err,
		}
	}
	defer conn.Close()

	// 发送SMB协商请求
	smbNegotiate := []byte{
		0x00, 0x00, 0x00, 0x85, // NetBIOS session header
		0xFF, 0x53, 0x4D, 0x42, // SMB header: SMB\n
		0x72,                   // Command: Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x53, 0xC8, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TID
		0x00, 0x00, // PID Low
		0x00, 0x00, // UID
		0x00, 0x00, // MID
		0x00,       // Word Count
		0x00, 0x00, // Byte Count
	}

	_, err = conn.Write(smbNegotiate)
	if err != nil {
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "SMB",
			Status:   "error",
			Error:    err,
		}
	}

	// 读取响应
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(d.config.Timeout))
	n, err := conn.Read(buffer)
	if err != nil {
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "SMB",
			Status:   "open",
			Banner:   "SMB service detected (no response)",
		}
	}

	response := buffer[:n]
	if len(response) >= 4 && response[0] == 0x00 && response[1] == 0x00 && response[2] == 0x00 {
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "SMB",
			Status:   "open",
			Banner:   "SMB service detected",
		}
	}

	return SMBUDPResult{
		Host:     host,
		Port:     port,
		Protocol: "SMB",
		Status:   "open",
		Banner:   "Unknown SMB response",
	}
}

// scanUDP 扫描UDP端口
func (d *SMBUDPDetector) scanUDP(host string, port int) SMBUDPResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// 尝试UDP连接
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "UDP",
			Status:   "error",
			Error:    err,
		}
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "UDP",
			Status:   "error",
			Error:    err,
		}
	}
	defer conn.Close()

	// 设置超时
	conn.SetDeadline(time.Now().Add(d.config.Timeout))

	// 发送测试数据（根据端口号发送不同的协议数据）
	testData := d.getUDPTestData(port)
	_, err = conn.Write(testData)
	if err != nil {
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "UDP",
			Status:   "filtered",
			Error:    err,
		}
	}

	// 尝试接收响应
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		// 超时或无响应，可能是端口开放但无服务
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return SMBUDPResult{
				Host:     host,
				Port:     port,
				Protocol: "UDP",
				Status:   "open|filtered",
				Banner:   "No response (port may be open)",
			}
		}
		return SMBUDPResult{
			Host:     host,
			Port:     port,
			Protocol: "UDP",
			Status:   "error",
			Error:    err,
		}
	}

	// 有响应，端口开放
	banner := fmt.Sprintf("UDP service detected: %s", hex.EncodeToString(response[:n]))
	return SMBUDPResult{
		Host:     host,
		Port:     port,
		Protocol: "UDP",
		Status:   "open",
		Banner:   banner,
	}
}

// getUDPTestData 根据端口号获取UDP测试数据
func (d *SMBUDPDetector) getUDPTestData(port int) []byte {
	switch port {
	case 53: // DNS
		return []byte{
			0x00, 0x00, // Transaction ID
			0x01, 0x00, // Flags: Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			0x03, 'c', 'o', 'm',
			0x00,       // Null terminator
			0x00, 0x01, // Type: A
			0x00, 0x01, // Class: IN
		}
	case 123: // NTP
		return []byte{
			0xE3, 0x00, 0x04, 0xFA, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	case 161: // SNMP
		return []byte{
			0x30, 0x29, // SNMP version 2c
			0x02, 0x01, 0x01, // Version: 1 (SNMPv2c)
			0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // Community: public
			0xA0, 0x1C, // GetRequest PDU
			0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // Request ID
			0x02, 0x01, 0x00, // Error status
			0x02, 0x01, 0x00, // Error index
			0x30, 0x0E, // Variable bindings
			0x30, 0x0C, // Sequence
			0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // sysDescr.0
			0x05, 0x00, // Null
		}
	default:
		// 通用UDP探测数据
		return []byte("HELLO")
	}
}

// DetectSMBVersion 检测SMB版本（高级功能）
func (d *SMBUDPDetector) DetectSMBVersion(host string) (string, error) {
	result := d.scanSMB(host, 445)
	if result.Error != nil {
		return "", result.Error
	}

	if result.Status == "open" {
		// 这里可以添加更详细的SMB版本检测逻辑
		return "SMB service detected (version detection not implemented)", nil
	}

	return "", fmt.Errorf("SMB service not found on %s", host)
}

// IsUDPPortOpen 检查UDP端口是否开放
func (d *SMBUDPDetector) IsUDPPortOpen(host string, port int) (bool, error) {
	result := d.scanUDP(host, port)
	return result.Status == "open" || result.Status == "open|filtered", result.Error
}

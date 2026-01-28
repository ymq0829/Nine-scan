package scanner

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"example.com/project/controller"
)

// 综合端口扫描任务结构
type comprehensivePortScanJob struct {
	host     string
	port     int
	protocol string // "tcp", "smb", "udp"
}

// 综合端口扫描结果结构
type comprehensivePortScanResult struct {
	host     string
	port     int
	protocol string
	open     bool
	banner   string
	error    error
}

// ComprehensiveScanResult 综合扫描结果类型
type ComprehensiveScanResult struct {
	TCPPorts map[string][]int                  // TCP开放端口
	SMBInfo  map[string]map[string]interface{} // SMB扫描结果
	UDPInfo  map[string]map[string]interface{} // UDP扫描结果
}

// 修改：PortScanner结构体支持多协议扫描
type PortScanner struct {
	targets          []string
	ports            []int
	logger           *controller.Logger
	timeout          time.Duration
	progressCallback func(current, total int)
	delayType        controller.DelayType
	delayValue       int
	enableUDP        bool // 启用UDP扫描
	// 移除enableSMB字段
}

// 修改：初始化函数，移除SMB参数
func NewPortScanner(targets []string, ports []int, logger *controller.Logger, timeout time.Duration) *PortScanner {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &PortScanner{
		targets:    targets,
		ports:      ports,
		logger:     logger,
		timeout:    timeout,
		delayType:  controller.ConstantDelay,
		delayValue: 100,
		enableUDP:  true, // 默认启用UDP扫描
		// 移除enableSMB设置
	}
}

// 修改：设置UDP启用状态（移除SMB参数）
func (s *PortScanner) SetUDPConfig(enableUDP bool) {
	s.enableUDP = enableUDP
	// 移除SMB相关设置
}

// 设置延迟配置
func (s *PortScanner) SetDelayConfig(delayType controller.DelayType, delayValue int) {
	s.delayType = delayType
	s.delayValue = delayValue
}

// TCP端口扫描函数
func (s *PortScanner) scanTCP(host string, port int) comprehensivePortScanResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err == nil {
		s.logger.Logf("%s:%d TCP端口开放", host, port)
		conn.Close()
		return comprehensivePortScanResult{
			host:     host,
			port:     port,
			protocol: "tcp",
			open:     true,
		}
	} else {
		s.logger.Logf("%s:%d TCP端口关闭或无法连接: %v", host, port, err)
		return comprehensivePortScanResult{
			host:     host,
			port:     port,
			protocol: "tcp",
			open:     false,
			error:    err,
		}
	}
}

// 删除整个scanSMB函数
// SMB扫描函数（基于TCP 445端口）
// func (s *PortScanner) scanSMB(host string, port int) comprehensivePortScanResult {
//     addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
//     conn, err := net.DialTimeout("tcp", addr, s.timeout)
//     if err != nil {
//         return comprehensivePortScanResult{
//             host:     host,
//             port:     port,
//             protocol: "smb",
//             open:     false,
//             error:    err,
//         }
//     }
//     defer conn.Close()
//
//     // 发送SMB协商请求
//     smbNegotiate := []byte{
//         0x00, 0x00, 0x00, 0x85, // NetBIOS session header
//         0xFF, 0x53, 0x4D, 0x42, // SMB header: SMB\n
//         0x72,                   // Command: Negotiate Protocol
//         0x00, 0x00, 0x00, 0x00, // Status
//         0x18,       // Flags
//         0x53, 0xC8, // Flags2
//         0x00, 0x00, // PID High
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security
//         0x00, 0x00, // Reserved
//         0x00, 0x00, 0x00, 0x00, // TID
//         0x00, 0x00, // PID Low
//         0x00, 0x00, // UID
//         0x00, 0x00, // MID
//         0x00,       // Word Count
//         0x00, 0x00, // Byte Count
//     }
//
//     _, err = conn.Write(smbNegotiate)
//     if err != nil {
//         return comprehensivePortScanResult{
//             host:     host,
//             port:     port,
//             protocol: "smb",
//             open:     true,
//             banner:   "SMB服务检测到（发送请求失败）",
//             error:    err,
//         }
//     }
//
//     // 读取响应
//     buffer := make([]byte, 1024)
//     conn.SetReadDeadline(time.Now().Add(s.timeout))
//     n, err := conn.Read(buffer)
//     if err != nil {
//         return comprehensivePortScanResult{
//             host:     host,
//             port:     port,
//             protocol: "smb",
//             open:     true,
//             banner:   "SMB服务检测到（无响应）",
//         }
//     }
//
//     response := buffer[:n]
//     if len(response) >= 4 && response[0] == 0x00 && response[1] == 0x00 && response[2] == 0x00 {
//         s.logger.Logf("%s:%d SMB服务检测到", host, port)
//         return comprehensivePortScanResult{
//             host:     host,
//             port:     port,
//             protocol: "smb",
//             open:     true,
//             banner:   "SMB服务检测到",
//         }
//     }
//
//     s.logger.Logf("%s:%d SMB服务检测到（未知响应）", host, port)
//     return comprehensivePortScanResult{
//         host:     host,
//         port:     port,
//         protocol: "smb",
//         open:     true,
//         banner:   "未知SMB响应",
//     }
// }

// UDP扫描函数
func (s *PortScanner) scanUDP(host string, port int) comprehensivePortScanResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return comprehensivePortScanResult{
			host:     host,
			port:     port,
			protocol: "udp",
			open:     false,
			error:    err,
		}
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return comprehensivePortScanResult{
			host:     host,
			port:     port,
			protocol: "udp",
			open:     false,
			error:    err,
		}
	}
	defer conn.Close()

	// 设置超时
	conn.SetDeadline(time.Now().Add(s.timeout))

	// 发送测试数据
	testData := s.getUDPTestData(port)
	_, err = conn.Write(testData)
	if err != nil {
		return comprehensivePortScanResult{
			host:     host,
			port:     port,
			protocol: "udp",
			open:     false,
			error:    err,
		}
	}

	// 尝试接收响应
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			s.logger.Logf("%s:%d UDP端口可能开放（无响应）", host, port)
			return comprehensivePortScanResult{
				host:     host,
				port:     port,
				protocol: "udp",
				open:     true,
				banner:   "无响应（端口可能开放）",
			}
		}
		return comprehensivePortScanResult{
			host:     host,
			port:     port,
			protocol: "udp",
			open:     false,
			error:    err,
		}
	}

	// 有响应，端口开放
	banner := fmt.Sprintf("UDP服务检测到: %s", hex.EncodeToString(response[:n]))
	s.logger.Logf("%s:%d UDP端口开放，响应: %s", host, port, hex.EncodeToString(response[:n]))
	return comprehensivePortScanResult{
		host:     host,
		port:     port,
		protocol: "udp",
		open:     true,
		banner:   banner,
	}
}

// 获取UDP测试数据
func (s *PortScanner) getUDPTestData(port int) []byte {
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
		return []byte("HELLO")
	}
}

// 综合端口扫描worker
func (s *PortScanner) comprehensivePortScanWorker(id int, jobs <-chan comprehensivePortScanJob, results chan<- comprehensivePortScanResult) {
	step := 0
	for job := range jobs {
		delay := controller.GetDelay(s.delayType, s.delayValue, step)
		if delay > 0 {
			time.Sleep(delay)
		}

		var result comprehensivePortScanResult
		switch job.protocol {
		case "tcp":
			result = s.scanTCP(job.host, job.port)
		case "udp":
			result = s.scanUDP(job.host, job.port)
			// 移除smb case
		}

		results <- result
		step++
	}
}

// SetProgressCallback 设置进度回调函数
func (s *PortScanner) SetProgressCallback(callback func(current, total int)) {
	s.progressCallback = callback
}

// ScanHosts 综合端口扫描方法（整合TCP、UDP）
func (s *PortScanner) ScanHosts(aliveHosts []string) (interface{}, error) {
	s.logger.Log("综合端口扫描开始，待扫描在线主机: " + fmt.Sprintf("%v", aliveHosts))
	s.logger.Logf("待扫描端口列表: %v", s.ports)
	s.logger.Logf("延迟配置: 类型=%s, 值=%dms", s.delayType, s.delayValue)
	s.logger.Logf("扫描协议: TCP=%v, UDP=%v", true, s.enableUDP)

	// 计算总任务数
	totalTasks := len(aliveHosts) * len(s.ports) // TCP扫描
	if s.enableUDP {
		totalTasks += len(aliveHosts) * len(s.ports) // UDP扫描
	}
	// 移除SMB任务计算

	jobs := make(chan comprehensivePortScanJob, totalTasks)
	results := make(chan comprehensivePortScanResult, totalTasks)

	// 启动worker
	const maxWorkers = 50
	for w := 1; w <= maxWorkers; w++ {
		go s.comprehensivePortScanWorker(w, jobs, results)
	}

	// 分发任务
	go func() {
		// TCP扫描任务
		for _, host := range aliveHosts {
			for _, port := range s.ports {
				jobs <- comprehensivePortScanJob{
					host:     host,
					port:     port,
					protocol: "tcp",
				}
			}
		}

		// 移除SMB扫描任务分发

		// UDP扫描任务（如果启用）
		if s.enableUDP {
			for _, host := range aliveHosts {
				for _, port := range s.ports {
					jobs <- comprehensivePortScanJob{
						host:     host,
						port:     port,
						protocol: "udp",
					}
				}
			}
		}

		close(jobs)
	}()

	// 收集结果
	comprehensiveResult := &ComprehensiveScanResult{
		TCPPorts: make(map[string][]int),
		UDPInfo:  make(map[string]map[string]interface{}),
		// 移除SMBInfo字段
	}
	var mu sync.Mutex
	completed := 0

	for i := 0; i < totalTasks; i++ {
		result := <-results
		mu.Lock()

		switch result.protocol {
		case "tcp":
			if result.open {
				comprehensiveResult.TCPPorts[result.host] = append(comprehensiveResult.TCPPorts[result.host], result.port)
			}
		case "udp":
			if result.open {
				if _, exists := comprehensiveResult.UDPInfo[result.host]; !exists {
					comprehensiveResult.UDPInfo[result.host] = make(map[string]interface{})
				}
				comprehensiveResult.UDPInfo[result.host][fmt.Sprintf("port_%d", result.port)] = map[string]interface{}{
					"status": "open",
					"banner": result.banner,
				}
			}
			// 移除smb case
		}

		mu.Unlock()
		completed++

		if s.progressCallback != nil {
			s.progressCallback(completed, totalTasks)
		}
	}

	s.logger.Log("综合端口扫描结束")
	return comprehensiveResult, nil
}

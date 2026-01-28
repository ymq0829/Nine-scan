//go:build windows
// +build windows

package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"example.com/project/controller"

	"syscall"

	"golang.org/x/sys/windows"
)

// 扫描方法常量
const (
	ScanMethodICMP = "ICMP扫描"
	ScanMethodTCP  = "TCP扫描"
)

// Windows Socket常量
const (
	AF_INET      = 2
	SOCK_RAW     = 3
	IPPROTO_ICMP = 1
	IPPROTO_IP   = 0
	SOL_SOCKET   = 0xffff
	SO_RCVTIMEO  = 0x1006
	SO_SNDTIMEO  = 0x1005
	IP_HDRINCL   = 2
	IP_TTL       = 4
)

// Windows错误码
const (
	WSAEACCES      = 10013
	WSAEINVAL      = 10022
	WSAETIMEDOUT   = 10060
	WSAEWOULDBLOCK = 10035
	WSAECONNRESET  = 10054 // 添加缺失的错误码
	WSAENETRESET   = 10052 // 添加缺失的错误码
	WSAENETDOWN    = 10050 // 添加缺失的错误码
)

// SockaddrInet4结构体尺寸
const (
	SOCKADDR_INET4_SIZE = 16 // sizeof(struct sockaddr_in)
)

// 结构体定义

// ICMPConfig holds configuration for ICMP operations
type ICMPConfig struct {
	Timeout time.Duration
	Retries int
	Logger  *controller.Logger
}

// HostInfo 主机信息结构体，包含存活状态和TTL值
type HostInfo struct {
	Host  string
	Alive bool
	TTL   int
}

// ICMPScanner ICMP扫描器结构体
type ICMPScanner struct {
	targets          []string
	logger           *controller.Logger
	config           ICMPConfig // 新增：统一配置管理
	progressCallback func(current, total int)
	delayType        controller.DelayType // 延迟类型
	delayValue       int                  // 延迟基础值
}

// 准备接收地址结构
type SockaddrIn struct {
	SinFamily uint16
	SinPort   uint16
	SinAddr   [4]byte
	SinZero   [8]byte
}

// Windows原始套接字包装器
type WindowsRawSocket struct {
	fd      windows.Handle
	timeout time.Duration
}

// ScanResult 扫描结果结构体
type ScanResult struct {
	Hosts      []HostInfo
	ScanMethod string
}

// 加载Windows Socket库
var (
	modws2_32       = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAStartup  = modws2_32.NewProc("WSAStartup")
	procWSACleanup  = modws2_32.NewProc("WSACleanup")
	procWSASocketW  = modws2_32.NewProc("WSASocketW")
	procClosesocket = modws2_32.NewProc("closesocket")
	procSetsockopt  = modws2_32.NewProc("setsockopt")
	procSendto      = modws2_32.NewProc("sendto")
	procRecvfrom    = modws2_32.NewProc("recvfrom")
)

// ========== 包级工具函数 ==========

// CheckAdminPrivileges 检查管理员权限（抽离为包级函数）
func CheckAdminPrivileges() bool {
	if runtime.GOOS != "windows" {
		return true
	}

	// 尝试打开需要管理员权限的设备
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// ParseIPRange 解析IP范围格式如"192.168.1.1-254"（抽离为包级函数）
func ParseIPRange(ipRange string) ([]string, error) {
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

	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", ipParts[0], ipParts[1], ipParts[2], i))
	}
	return ips, nil
}

// ValidateIP 验证IP地址格式（新增通用函数）
func ValidateIP(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("无效的IP地址: %s", ip)
	}
	if parsedIP.To4() == nil {
		return fmt.Errorf("不是IPv4地址: %s", ip)
	}
	return nil
}

// ========== Windows原始套接字相关函数 ==========

// 初始化Windows Socket
func initWinsock() error {
	type WSAData struct {
		WVersion       uint16
		WHighVersion   uint16
		SzDescription  [257]byte
		SzSystemStatus [129]byte
		IMaxSockets    uint16
		IMaxUdpDg      uint16
		LpVendorInfo   *byte
	}

	var wsaData WSAData
	ret, _, err := procWSAStartup.Call(uintptr(0x202), uintptr(unsafe.Pointer(&wsaData)))
	if ret != 0 {
		return fmt.Errorf("WSAStartup失败: %v", err)
	}
	return nil
}

// 清理Windows Socket
func cleanupWinsock() {
	procWSACleanup.Call()
}

// CreateWindowsRawSocket 使用Windows API创建原始套接字
func CreateWindowsRawSocket() (*WindowsRawSocket, error) {
	// 初始化Winsock
	if err := initWinsock(); err != nil {
		return nil, err
	}

	// 使用WSASocketW创建套接字，比socket()有更好的兼容性
	// WSA_FLAG_OVERLAPPED = 0x01
	ret, _, err := procWSASocketW.Call(
		uintptr(AF_INET),
		uintptr(SOCK_RAW),
		uintptr(IPPROTO_ICMP),
		0,    // lpProtocolInfo
		0,    // g
		0x01, // dwFlags: 使用 WSA_FLAG_OVERLAPPED，启用异步I/O
	)

	if windows.Handle(ret) == windows.InvalidHandle {
		cleanupWinsock()
		// 添加详细的错误信息
		if errno, ok := err.(syscall.Errno); ok {
			return nil, fmt.Errorf("WSASocketW失败: errno=%d (可能缺少权限或防火墙阻止)", errno)
		}
		return nil, fmt.Errorf("WSASocketW失败: %v", err)
	}

	// 使用同一个实例进行设置并返回（修复：不要返回一个新的未初始化实例）
	sock := &WindowsRawSocket{fd: windows.Handle(ret)}
	if err := sock.SetTimeout(100 * time.Millisecond); err != nil {
		// 关闭套接字并清理
		sock.Close()
		return nil, fmt.Errorf("套接字设置超时失败: %v", err)
	}

	return sock, nil
}

// Close 关闭套接字
func (s *WindowsRawSocket) Close() error {
	if s.fd == windows.InvalidHandle {
		return nil
	}

	ret, _, _ := procClosesocket.Call(uintptr(s.fd))
	cleanupWinsock()

	s.fd = windows.InvalidHandle
	if ret != 0 {
		return fmt.Errorf("关闭套接字失败")
	}
	return nil
}

// SetTimeout 设置套接字超时
func (s *WindowsRawSocket) SetTimeout(timeout time.Duration) error {
	s.timeout = timeout

	// 设置接收超时
	timeoutMs := int32(timeout / time.Millisecond)
	ret, _, err := procSetsockopt.Call(
		uintptr(s.fd),
		uintptr(SOL_SOCKET),
		uintptr(SO_RCVTIMEO),
		uintptr(unsafe.Pointer(&timeoutMs)),
		uintptr(unsafe.Sizeof(timeoutMs)),
	)

	if ret != 0 {
		return fmt.Errorf("设置接收超时失败: %v", err)
	}

	// 设置发送超时
	ret, _, err = procSetsockopt.Call(
		uintptr(s.fd),
		uintptr(SOL_SOCKET),
		uintptr(SO_SNDTIMEO),
		uintptr(unsafe.Pointer(&timeoutMs)),
		uintptr(unsafe.Sizeof(timeoutMs)),
	)

	if ret != 0 {
		return fmt.Errorf("设置发送超时失败: %v", err)
	}

	return nil
}

// SendICMPEcho 发送ICMP Echo请求
// 在SendICMPEcho函数中添加更安全的指针操作
func (s *WindowsRawSocket) SendICMPEcho(targetIP net.IP, id, seq uint16) error {
	// 确保packet不为空
	packet := createICMPEchoPacket(id, seq)
	if len(packet) == 0 {
		return fmt.Errorf("ICMP包创建失败")
	}

	// 准备目标地址结构
	var addr SockaddrIn
	addr.SinFamily = AF_INET
	addr.SinPort = 0
	copy(addr.SinAddr[:], targetIP.To4())

	// 添加安全检查
	if s.fd == windows.InvalidHandle {
		return fmt.Errorf("套接字无效")
	}

	// 发送数据
	ret, _, err := procSendto.Call(
		uintptr(s.fd),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		0, // flags
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Sizeof(addr)),
	)

	// 发送失败通常会有非零 err 或者返回 SOCKET_ERROR (-1)
	if int(ret) == -1 {
		return fmt.Errorf("发送失败: %v", err)
	}

	return nil
}

func (s *WindowsRawSocket) ReceiveICMPResponse() ([]byte, net.IP, error) {
	buf := make([]byte, 1500)
	var from SockaddrIn
	fromLen := uint32(unsafe.Sizeof(from))

	ret, _, err := procRecvfrom.Call(
		uintptr(s.fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		uintptr(unsafe.Pointer(&from)),
		uintptr(unsafe.Pointer(&fromLen)),
	)

	// 更精确的错误检测（保留对 Errno 的判断）
	if int32(ret) == -1 { // SOCKET_ERROR
		if errno, ok := err.(syscall.Errno); ok {
			switch errno {
			case WSAEWOULDBLOCK, WSAETIMEDOUT:
				return nil, nil, fmt.Errorf("接收超时")
			case WSAECONNRESET, WSAENETRESET, WSAENETDOWN:
				return nil, nil, fmt.Errorf("网络错误: %d", errno)
			default:
				return nil, nil, fmt.Errorf("接收失败: errno=%d", errno)
			}
		}
		return nil, nil, fmt.Errorf("接收失败: SOCKET_ERROR")
	}

	// 正确处理返回值
	if ret == 0 {
		return nil, nil, fmt.Errorf("连接关闭")
	}

	if ret > uintptr(len(buf)) {
		return nil, nil, fmt.Errorf("接收到非法长度: %d", int(ret))
	}

	r := int(ret)
	if r <= 0 {
		return nil, nil, fmt.Errorf("接收到非法长度: %d", r)
	}

	srcIP := net.IPv4(from.SinAddr[0], from.SinAddr[1], from.SinAddr[2], from.SinAddr[3])
	return buf[:r], srcIP, nil
}

// ========== ICMP核心逻辑函数 ==========

// SendEchoRequest 发送ICMP Echo请求并等待响应（专注ICMP扫描，不内置TCP兜底）
func SendEchoRequest(target string, config ICMPConfig) (bool, int, error) {
	// 验证IP地址格式
	if err := ValidateIP(target); err != nil {
		return false, -1, fmt.Errorf("IP地址验证失败: %v", err)
	}

	// 检查管理员权限
	if !CheckAdminPrivileges() {
		return false, -1, fmt.Errorf("需要管理员权限才能使用ICMP原始套接字")
	}
	// 使用Windows原始套接字进行ICMP扫描
	alive, ttl, err := sendWithWindowsRawSocket(target, config)
	if err != nil {
		return false, -1, fmt.Errorf("ICMP扫描失败: %v", err)
	}

	return alive, ttl, nil
}

// sendWithWindowsRawSocket 使用Windows API原始套接字（专注ICMP逻辑）
func sendWithWindowsRawSocket(target string, config ICMPConfig) (bool, int, error) {
	defer func() {
		if r := recover(); r != nil {
			if config.Logger != nil {
				config.Logger.Logf("Windows原始套接字操作发生panic: %v", r)
			}
		}
	}()

	// 解析目标IP
	dstIP := net.ParseIP(target)
	if dstIP == nil {
		return false, 0, fmt.Errorf("无效的IP地址: %s", target)
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		return false, 0, fmt.Errorf("不是IPv4地址: %s", target)
	}

	// 创建Windows原始套接字
	sock, err := CreateWindowsRawSocket()
	if err != nil {
		return false, 0, fmt.Errorf("创建原始套接字失败: %v", err)
	}
	defer sock.Close()

	// 设置超时
	if err := sock.SetTimeout(config.Timeout); err != nil {
		return false, 0, fmt.Errorf("设置套接字超时失败: %v", err)
	}

	// 尝试发送和接收ICMP包
	id := uint16(os.Getpid() & 0xffff)
	for seq := 1; seq <= config.Retries; seq++ {
		if config.Logger != nil {
			config.Logger.Logf("Windows原始套接字: 发送ICMP到 %s (重试 %d)", target, seq)
		}

		// 发送ICMP Echo
		err = sock.SendICMPEcho(dstIP, id, uint16(seq))
		if err != nil {
			if config.Logger != nil {
				config.Logger.Logf("发送失败: %v", err)
			}
			continue
		}
		// 接收响应
		response, srcIP, err := sock.ReceiveICMPResponse()
		if err != nil {
			if strings.Contains(err.Error(), "接收超时") {
				if config.Logger != nil {
					config.Logger.Logf("接收超时: %s", target)
				}
			} else {
				return false, 0, fmt.Errorf("接收失败: %v", err)
			}
			continue
		}

		// 验证响应
		if len(response) >= 20 {
			// 提取TTL（IP头第9字节）
			ttl := int(response[8])

			// 检查是否来自目标
			if srcIP.Equal(dstIP) {
				// 检查是否是ICMP Echo Reply (Type=0)
				ipHeaderLen := (response[0] & 0x0F) * 4
				if len(response) >= int(ipHeaderLen+8) {
					icmpType := response[ipHeaderLen]
					if icmpType == 0 { // ICMP Echo Reply
						// 验证ID是否匹配
						icmpID := uint16(response[ipHeaderLen+4])<<8 | uint16(response[ipHeaderLen+5])
						if icmpID == id {
							if config.Logger != nil {
								config.Logger.Logf("Windows原始套接字收到来自 %s 的响应，TTL: %d", target, ttl)
							}
							return true, ttl, nil
						}
					}
				}
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	return false, 0, nil
}

// ========== TCP扫描函数（用于降级） ==========

// scanWithTCP 使用TCP连接进行存活性检测（独立函数）
func scanWithTCP(target string, config ICMPConfig) (bool, error) {
	// 使用常见的TCP端口进行连接测试
	commonPorts := []int{80, 443, 22, 3389, 21, 23, 25, 53, 110, 143, 445, 3306, 8080}

	for _, port := range commonPorts {
		addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, config.Timeout)
		if err == nil {
			conn.Close()
			return true, nil
		}
	}

	return false, nil
}

// ========== ICMP包构建函数 ==========

// createICMPEchoPacket 创建ICMP Echo请求包
func createICMPEchoPacket(id, seq uint16) []byte {
	// ICMP Echo Request:
	// Type(8) + Code(0) + Checksum(0) + ID + Seq + Data

	packet := make([]byte, 8+8) // 8字节头 + 8字节数据
	packet[0] = 8               // Type: Echo Request
	packet[1] = 0               // Code: 0
	// Checksum位置2-3，先填0
	binary.BigEndian.PutUint16(packet[4:6], id)  // ID
	binary.BigEndian.PutUint16(packet[6:8], seq) // Sequence
	copy(packet[8:], []byte("pingdata"))         // Data

	// 计算校验和
	checksum := calculateChecksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)

	return packet
}

// calculateChecksum 计算ICMP校验和
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

// ========== ICMPScanner结构体方法 ==========

// NewICMPScanner creates a new ICMPScanner
func NewICMPScanner(targets []string, logger *controller.Logger) *ICMPScanner {
	return &ICMPScanner{
		targets: targets,
		logger:  logger,
		config: ICMPConfig{
			Timeout: 3 * time.Second,
			Retries: 2,
			Logger:  logger,
		},
		delayType:  controller.ConstantDelay, // 默认延迟类型
		delayValue: 100,                      // 默认延迟值
	}
}

// SetConfig 设置ICMP配置参数
func (s *ICMPScanner) SetConfig(timeout time.Duration, retries int) {
	s.config.Timeout = timeout
	s.config.Retries = retries
}

// 新增：设置延迟配置
func (s *ICMPScanner) SetDelayConfig(delayType controller.DelayType, delayValue int) {
	s.delayType = delayType
	s.delayValue = delayValue
}

// SetProgressCallback 设置进度回调函数
func (s *ICMPScanner) SetProgressCallback(callback func(current, total int)) {
	s.progressCallback = callback
}

// parseTargets 解析目标列表（使用包级函数）
func (s *ICMPScanner) parseTargets() []string {
	var targetsToScan []string
	for _, target := range s.targets {
		if strings.Contains(target, "-") {
			// 尝试解析IP范围
			if ips, err := ParseIPRange(target); err == nil {
				targetsToScan = append(targetsToScan, ips...)
			} else {
				s.logger.Logf("无法解析IP范围 %s: %v", target, err)
			}
		} else {
			// 单个IP地址
			targetsToScan = append(targetsToScan, target)
		}
	}
	return targetsToScan
}

// Scan 探测主机存活性（改进：按目标IP逐个ICMP→TCP降级）
func (s *ICMPScanner) Scan() (interface{}, error) {
	targetsToScan := s.parseTargets()
	s.logger.Log("主机存活性扫描开始，目标列表: " + fmt.Sprintf("%v", targetsToScan))

	// 通知初始进度
	if s.progressCallback != nil {
		s.progressCallback(0, len(targetsToScan))
	}

	// 改进：检查管理员权限，但按目标IP逐个处理
	var aliveHosts []HostInfo
	var scanMethod string

	if CheckAdminPrivileges() {
		s.logger.Log("具有管理员权限，使用ICMP扫描，失败的目标将回退到TCP扫描")
		aliveHosts, scanMethod = s.scanWithICMPAndFallback(targetsToScan)
	} else {
		s.logger.Log("无管理员权限，全部使用TCP扫描")
		aliveHosts = s.scanWithTCP(targetsToScan)
		scanMethod = ScanMethodTCP
	}

	s.logger.Logf("%s完成，发现%d个在线主机", scanMethod, len(aliveHosts))
	return ScanResult{
		Hosts:      aliveHosts,
		ScanMethod: scanMethod,
	}, nil
}

// scanWithICMPAndFallback 使用ICMP扫描，失败的目标回退到TCP扫描（改进：返回扫描方法描述）
func (s *ICMPScanner) scanWithICMPAndFallback(targets []string) ([]HostInfo, string) {
	const maxWorkers = 5
	const globalTimeout = 30 * time.Second

	totalTargets := len(targets)
	jobs := make(chan string, totalTargets)
	results := make(chan HostInfo, totalTargets)
	var aliveHosts []HostInfo

	// 跟踪是否发生了回退
	fallbackOccurred := false

	// context 用于取消 worker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// worker 函数，支持ICMP失败后回退到TCP
	worker := func(id int) {
		defer wg.Done()
		step := 0
		for {
			select {
			case <-ctx.Done():
				return
			case target, ok := <-jobs:
				if !ok {
					return
				}
				// 延迟控制
				delay := controller.GetDelay(s.delayType, s.delayValue, step)
				if delay > 0 {
					s.logger.Logf("ICMP Worker %d: 步骤=%d, 延迟类型=%s, 基础值=%dms, 实际延迟=%v, 目标=%s",
						id, step, s.delayType, s.delayValue, delay, target)
					time.Sleep(delay)
				}

				// 首先尝试ICMP扫描
				alive, ttl, err := SendEchoRequest(target, s.config)
				if err != nil {
					// 详细记录ICMP失败原因
					s.logger.Logf("ICMP扫描失败 %s: %v，将尝试TCP回退扫描", target, err)

					// ICMP失败，回退到TCP扫描
					tcpAlive, tcpErr := s.fallbackToTCP(target)
					if tcpErr != nil {
						s.logger.Logf("TCP回退扫描失败 %s: %v", target, tcpErr)
						results <- HostInfo{Host: target, Alive: false, TTL: -1}
					} else if tcpAlive {
						s.logger.Logf("TCP回退扫描成功 %s: 主机在线", target)
						results <- HostInfo{Host: target, Alive: true, TTL: -1}
						fallbackOccurred = true
					} else {
						s.logger.Logf("TCP回退扫描 %s: 主机不在线", target)
						results <- HostInfo{Host: target, Alive: false, TTL: -1}
					}
				} else if alive {
					s.logger.Logf("ICMP扫描成功 %s: 主机在线，TTL=%d", target, ttl)
					results <- HostInfo{Host: target, Alive: true, TTL: ttl}
				} else {
					s.logger.Logf("ICMP扫描 %s: 主机不在线", target)
					// ICMP扫描失败但无错误（如超时），也回退到TCP扫描
					tcpAlive, tcpErr := s.fallbackToTCP(target)
					if tcpErr != nil {
						s.logger.Logf("TCP回退扫描失败 %s: %v", target, tcpErr)
						results <- HostInfo{Host: target, Alive: false, TTL: -1}
					} else if tcpAlive {
						s.logger.Logf("TCP回退扫描成功 %s: 主机在线", target)
						results <- HostInfo{Host: target, Alive: true, TTL: -1}
						fallbackOccurred = true
					} else {
						s.logger.Logf("TCP回退扫描 %s: 主机不在线", target)
						results <- HostInfo{Host: target, Alive: false, TTL: -1}
					}
				}
				step++
			}
		}
	}

	// 启动 worker
	wg.Add(maxWorkers)
	for w := 0; w < maxWorkers; w++ {
		go worker(w)
	}

	// 分发任务
	go func() {
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
	}()

	// 在 worker 全部退出后关闭 results 通道
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集结果并处理超时
	completed := 0
	timer := time.NewTimer(globalTimeout)
	defer func() {
		if !timer.Stop() {
			<-timer.C
		}
	}()

collectLoop:
	for {
		select {
		case result, ok := <-results:
			if !ok {
				break collectLoop
			}
			if result.Alive {
				aliveHosts = append(aliveHosts, result)
			}
			completed++
			if s.progressCallback != nil {
				s.progressCallback(completed, totalTargets)
			}
			if completed >= totalTargets {
				break collectLoop
			}
		case <-timer.C:
			s.logger.Logf("扫描超时，已完成 %d/%d 个目标", completed, totalTargets)
			remaining := totalTargets - completed
			for j := 0; j < remaining; j++ {
				completed++
				if s.progressCallback != nil {
					s.progressCallback(completed, totalTargets)
				}
			}
			cancel()
		}
	}

	// 根据是否发生回退来设置扫描方法描述
	scanMethod := ScanMethodICMP
	if fallbackOccurred {
		scanMethod = ScanMethodICMP + "（部分回退到TCP）"
	}

	return aliveHosts, scanMethod
}

// fallbackToTCP 单个目标的TCP回退扫描（新增方法）
func (s *ICMPScanner) fallbackToTCP(target string) (bool, error) {
	// 使用常见的TCP端口进行连接测试
	commonPorts := []int{80, 443, 22, 3389, 21, 23, 25, 53, 110, 143, 445, 3306, 8080}

	for _, port := range commonPorts {
		addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, s.config.Timeout)
		if err == nil {
			conn.Close()
			return true, nil
		}
		// 记录每个端口的连接失败原因（可选，避免日志过多）
		// s.logger.Logf("TCP回退扫描 %s:%d 连接失败: %v", target, port, err)
	}

	return false, nil
}

// scanWithTCP 使用TCP进行主机存活性扫描（降级方案）
func (s *ICMPScanner) scanWithTCP(targets []string) []HostInfo {
	// 使用常见的TCP端口
	commonPorts := []int{80, 443, 22, 3389, 21, 23, 25, 53, 110, 143, 445, 3306, 8080}

	// 创建PortScanner实例并设置延迟配置
	portScanner := NewPortScanner(targets, commonPorts, s.logger, s.config.Timeout)
	portScanner.SetDelayConfig(s.delayType, s.delayValue)

	// 设置进度回调
	if s.progressCallback != nil {
		portScanner.SetProgressCallback(s.progressCallback)
	}

	// 执行端口扫描 - 修复：使用ScanHosts方法替代已删除的Scan方法
	result, err := portScanner.ScanHosts(targets)
	if err != nil {
		s.logger.Logf("TCP扫描失败: %v", err)
		return []HostInfo{}
	}

	// 转换结果格式
	var aliveHosts []HostInfo
	if comprehensiveResult, ok := result.(*ComprehensiveScanResult); ok {
		for target, ports := range comprehensiveResult.TCPPorts {
			if len(ports) > 0 {
				aliveHosts = append(aliveHosts, HostInfo{
					Host:  target,
					Alive: true,
					TTL:   -1, // TCP扫描无法获取TTL
				})
			}
		}
	}

	return aliveHosts
}

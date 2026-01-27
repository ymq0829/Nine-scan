//go:build windows
// +build windows

package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"example.com/project/controller"

	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
)

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

// 在ICMPScanner结构体中添加延迟控制字段
type ICMPScanner struct {
	targets          []string
	logger           *controller.Logger
	progressCallback func(current, total int)
	delayType        controller.DelayType // 新增：延迟类型
	delayValue       int                  // 新增：延迟基础值
}

// 准备接收地址结构
type SockaddrIn struct {
	SinFamily uint16
	SinPort   uint16
	SinAddr   [4]byte
	SinZero   [8]byte
}

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
)

// SockaddrInet4结构体尺寸
const (
	SOCKADDR_INET4_SIZE = 16 // sizeof(struct sockaddr_in)
)

// Windows原始套接字包装器
type WindowsRawSocket struct {
	fd      windows.Handle
	timeout time.Duration
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
		0,             // lpProtocolInfo
		0,             // g
		uintptr(0x01), // dwFlags
	)

	if windows.Handle(ret) == windows.InvalidHandle {
		cleanupWinsock()
		return nil, fmt.Errorf("WSASocketW失败: %v", err)
	}

	return &WindowsRawSocket{fd: windows.Handle(ret)}, nil
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

	if int(ret) == -1 {
		return fmt.Errorf("发送失败: %v", err)
	}

	return nil
}

// ReceiveICMPResponse 接收ICMP响应（已做安全长度检查，避免 slice 越界 panic）
func (s *WindowsRawSocket) ReceiveICMPResponse() ([]byte, net.IP, error) {
	buf := make([]byte, 1500)
	var from SockaddrIn
	fromLen := uint32(unsafe.Sizeof(from))

	ret, _, err := procRecvfrom.Call(
		uintptr(s.fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, // flags
		uintptr(unsafe.Pointer(&from)),
		uintptr(unsafe.Pointer(&fromLen)),
	)

	// 检查返回错误（-1 -> SOCKET_ERROR）或 err
	if int(ret) == -1 {
		// 检查是否为超时
		if errno, ok := err.(syscall.Errno); ok {
			switch errno {
			case WSAEWOULDBLOCK, WSAETIMEDOUT:
				return nil, nil, fmt.Errorf("接收超时")
			}
		}
		return nil, nil, fmt.Errorf("接收失败: %v", err)
	}

	// 安全地将 ret 转为 int 并做边界检查，防止 uintptr 表现为大值导致切片越界
	r := int(ret)
	if r <= 0 || r > len(buf) {
		return nil, nil, fmt.Errorf("接收到非法长度: %d", r)
	}

	// 提取源IP地址
	srcIP := net.IPv4(from.SinAddr[0], from.SinAddr[1], from.SinAddr[2], from.SinAddr[3])

	return buf[:r], srcIP, nil
}

// 简化的提权检查，使用与main.go相同的逻辑
func (s *ICMPScanner) ensureAdminPrivileges() bool {
	if runtime.GOOS != "windows" {
		return true // 非Windows平台不需要提权
	}

	// 使用与main.go相同的权限检查方法
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err == nil {
		s.logger.Log("具有管理员权限，可以执行ICMP扫描")
		return true // 已经是管理员
	}

	s.logger.Log("当前不是管理员权限，ICMP扫描可能受限，将使用TCP扫描")
	return false
}

// SendEchoRequest sends an ICMP echo request to the target and returns TTL value
func SendEchoRequest(target string, config ICMPConfig) (bool, int, error) {
	// 尝试使用Windows原始套接字API
	return sendWithWindowsRawSocket(target, config)
}

// sendWithWindowsRawSocket 使用Windows API原始套接字
func sendWithWindowsRawSocket(target string, config ICMPConfig) (bool, int, error) {
	defer func() {
		if r := recover(); r != nil {
			if config.Logger != nil {
				config.Logger.Logf("Windows原始套接字操作发生panic: %v", r)
			}
		}
	}()
	// 检查管理员权限
	if !checkAdminPrivileges() {
		if config.Logger != nil {
			config.Logger.Log("需要管理员权限才能使用原始套接字")
		}
		return sendWithIcmpOnly(target, config)
	}

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
		if config.Logger != nil {
			config.Logger.Logf("创建Windows原始套接字失败: %v", err)
		}
		return sendWithIcmpOnly(target, config)
	}
	defer sock.Close()

	// 设置超时
	sock.SetTimeout(config.Timeout)

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
			if err.Error() == "接收超时" {
				if config.Logger != nil {
					config.Logger.Logf("接收超时: %s", target)
				}
			} else if config.Logger != nil {
				config.Logger.Logf("接收失败: %v", err)
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

// sendWithIcmpOnly 纯icmp包模式（回退方案）
func sendWithIcmpOnly(target string, config ICMPConfig) (bool, int, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, 0, err
	}
	defer c.Close()

	// Prepare ICMP message
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return false, 0, err
	}

	for i := 0; i < config.Retries; i++ {
		if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(target)}); err != nil {
			if config.Logger != nil {
				config.Logger.Logf("发送ICMP请求失败: %v", err)
			}
			continue
		}

		if err := c.SetReadDeadline(time.Now().Add(config.Timeout)); err != nil {
			return false, 0, err
		}

		rb := make([]byte, 1500)
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if config.Logger != nil {
					config.Logger.Logf("接收ICMP响应超时: %v", target)
				}
				continue
			}
			if config.Logger != nil {
				config.Logger.Logf("接收ICMP响应失败: %v", err)
			}
			continue
		}

		// 检查是否来自目标
		var peerIP string
		if peer != nil {
			if ipAddr, ok := peer.(*net.IPAddr); ok {
				peerIP = ipAddr.IP.String()
			}
		}
		if peerIP != "" && peerIP != target {
			continue
		}

		// 解析ICMP消息
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			if config.Logger != nil {
				config.Logger.Logf("解析ICMP消息失败: %v", err)
			}
			continue
		}

		// 检查是否是Echo Reply
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			if config.Logger != nil {
				config.Logger.Logf("收到来自 %s 的Echo Reply", target)
			}
			// 对于纯icmp包模式，返回默认TTL值
			ttl := getDefaultTTL(target)
			return true, ttl, nil
		case ipv4.ICMPTypeDestinationUnreachable:
			if config.Logger != nil {
				config.Logger.Logf("目标 %s 不可达", target)
			}
			return false, 0, nil
		default:
			if config.Logger != nil {
				config.Logger.Logf("收到来自 %s 的未知ICMP类型: %v", target, rm.Type)
			}
		}
	}

	return false, 0, nil
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

// checkAdminPrivileges 检查管理员权限
func checkAdminPrivileges() bool {
	if runtime.GOOS != "windows" {
		return true
	}

	// 尝试打开需要管理员权限的设备
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// getDefaultTTL 根据目标IP返回合理的默认TTL值
func getDefaultTTL(target string) int {
	ip := net.ParseIP(target)
	if ip == nil {
		return 64 // 默认值
	}

	// 判断是否为本地网络
	if isLocalNetwork(target) {
		// 本地网络：Windows系统通常返回128，Linux系统返回64
		return 128 // 假设本地网络使用Windows系统
	} else {
		// 远程网络：TTL会递减，通常为64-128之间的值
		return 64 // 假设远程网络使用Linux系统
	}
}

// isLocalNetwork 判断目标是否为本地网络
func isLocalNetwork(target string) bool {
	ip := net.ParseIP(target)
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

// SendAndReceive 发送ICMP请求并接收响应（ICMPScanner版本）
func (s *ICMPScanner) SendAndReceive(target string) (bool, int, error) {
	config := ICMPConfig{
		Timeout: 3 * time.Second,
		Retries: 1,
		Logger:  s.logger,
	}
	return SendEchoRequest(target, config)
}

// NewICMPScanner creates a new ICMPScanner

// 修改：初始化函数，添加延迟配置参数
func NewICMPScanner(targets []string, logger *controller.Logger) *ICMPScanner {
	return &ICMPScanner{
		targets:    targets,
		logger:     logger,
		delayType:  controller.ConstantDelay, // 默认延迟类型
		delayValue: 100,                      // 默认延迟值
	}
}

// 新增：设置延迟配置
func (s *ICMPScanner) SetDelayConfig(delayType controller.DelayType, delayValue int) {
	s.delayType = delayType
	s.delayValue = delayValue
}

// 修改：scanWithWindowsAPI函数，添加延迟控制
// 修改worker函数，添加更详细的延迟日志
func (s *ICMPScanner) scanWithWindowsAPI(targets []string) []HostInfo {
	const maxWorkers = 5 // 减少并发数，避免资源竞争
	totalTargets := len(targets)

	jobs := make(chan string, totalTargets)
	results := make(chan HostInfo, totalTargets)
	var aliveHosts []HostInfo

	// 修改：添加延迟控制的worker函数
	worker := func(id int, jobs <-chan string, results chan<- HostInfo) {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Logf("ICMP扫描worker发生panic: %v", r)
				results <- HostInfo{}
			}
		}()

		step := 0
		for target := range jobs {
			// 在每个任务前添加延迟
			delay := controller.GetDelay(s.delayType, s.delayValue, step)
			if delay > 0 {
				// 改进：显示更详细的延迟信息
				s.logger.Logf("ICMP Worker %d: 步骤=%d, 延迟类型=%s, 基础值=%dms, 实际延迟=%v, 目标=%s",
					id, step, s.delayType, s.delayValue, delay, target)
				time.Sleep(delay)
			}

			config := ICMPConfig{
				Timeout: 2 * time.Second,
				Retries: 2,
				Logger:  s.logger,
			}
			alive, ttl, _ := SendEchoRequest(target, config)
			if alive {
				results <- HostInfo{
					Host:  target,
					Alive: true,
					TTL:   ttl,
				}
			} else {
				results <- HostInfo{}
			}
			step++
		}
	}

	// 启动worker
	for w := 0; w < maxWorkers; w++ {
		go worker(w, jobs, results)
	}

	// 分发任务
	go func() {
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
	}()

	// 收集结果
	completed := 0
	for i := 0; i < totalTargets; i++ {
		result := <-results
		if result.Alive {
			aliveHosts = append(aliveHosts, result)
		}

		completed++
		if s.progressCallback != nil {
			s.progressCallback(completed, totalTargets)
		}
	}

	return aliveHosts
}

// 修改：scanWithTCPEnhanced函数，添加延迟控制
func (s *ICMPScanner) scanWithTCPEnhanced(targets []string) []HostInfo {
	ports := []string{"80", "443", "22", "3389", "21", "23", "25", "53", "110", "143", "445", "3306", "8080"}
	const maxWorkers = 20

	type scanJob struct {
		target string
		port   string
	}

	type scanResult struct {
		target string
		alive  bool
	}

	totalJobs := len(targets) * len(ports)
	completedJobs := 0

	jobs := make(chan scanJob, totalJobs)
	results := make(chan scanResult, totalJobs)
	aliveMap := make(map[string]bool)

	// 修改：添加延迟控制的worker函数
	worker := func(id int, jobs <-chan scanJob, results chan<- scanResult) {
		step := 0
		for job := range jobs {
			// 在每个任务前添加延迟
			delay := controller.GetDelay(s.delayType, s.delayValue, step)
			if delay > 0 {
				s.logger.Logf("TCP Worker %d: 延迟 %v 后扫描 %s:%s", id, delay, job.target, job.port)
				time.Sleep(delay)
			}

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(job.target, job.port), 5*time.Second)
			alive := err == nil
			if alive {
				conn.Close()
			}
			results <- scanResult{target: job.target, alive: alive}
			step++
		}
	}

	// 启动worker
	for w := 0; w < maxWorkers; w++ {
		go worker(w, jobs, results)
	}

	// 分发任务
	go func() {
		for _, target := range targets {
			for _, port := range ports {
				jobs <- scanJob{target: target, port: port}
			}
		}
		close(jobs)
	}()

	// 收集结果
	for i := 0; i < totalJobs; i++ {
		result := <-results
		if result.alive {
			aliveMap[result.target] = true
		}

		// 更新进度
		completedJobs++
		if s.progressCallback != nil {
			progress := (completedJobs * len(targets)) / totalJobs
			s.progressCallback(progress, len(targets))
		}
	}
	close(results)

	// 转换为HostInfo切片，为TCP扫描的主机设置默认TTL值
	var aliveHosts []HostInfo
	for target := range aliveMap {
		aliveHosts = append(aliveHosts, HostInfo{
			Host:  target,
			Alive: true,
			TTL:   0, // TCP扫描无法获取TTL，设为0
		})
	}

	s.logger.Logf("TCP存活性扫描完成，发现%d个在线主机", len(aliveHosts))
	return aliveHosts
}

// SetProgressCallback 设置进度回调函数
func (s *ICMPScanner) SetProgressCallback(callback func(current, total int)) {
	s.progressCallback = callback
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

	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", ipParts[0], ipParts[1], ipParts[2], i))
	}
	return ips, nil
}

// Scan 探测主机存活性（ICMP Echo请求或TCP连接检查）
// 返回包含TTL值的HostInfo切片
func (s *ICMPScanner) Scan() (interface{}, error) {
	targetsToScan := s.parseTargets()
	s.logger.Log("主机存活性扫描开始，目标列表: " + fmt.Sprintf("%v", targetsToScan))

	// 通知初始进度
	if s.progressCallback != nil {
		s.progressCallback(0, len(targetsToScan))
	}

	// 检查管理员权限
	if s.ensureAdminPrivileges() {
		// 使用Windows API进行ICMP扫描
		s.logger.Log("具有管理员权限，使用Windows原始套接字API进行ICMP扫描")

		aliveHosts := s.scanWithWindowsAPI(targetsToScan)
		s.logger.Logf("Windows原始套接字API扫描完成，发现%d个在线主机", len(aliveHosts))
		return aliveHosts, nil
	}

	s.logger.Log("没有管理员权限，使用TCP扫描进行主机存活性检测")
	return s.scanWithTCPEnhanced(targetsToScan), nil
}

// parseTargets 解析目标IP范围
func (s *ICMPScanner) parseTargets() []string {
	var targetsToScan []string
	for _, target := range s.targets {
		if strings.Contains(target, "-") {
			ips, err := parseIPRange(target)
			if err != nil {
				s.logger.Errorf("解析IP范围%s失败: %v", target, err)
				continue
			}
			targetsToScan = append(targetsToScan, ips...)
		} else {
			targetsToScan = append(targetsToScan, target)
		}
	}
	return targetsToScan
}

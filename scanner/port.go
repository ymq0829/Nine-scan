package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"example.com/project/controller" // 引入日志模块
)

type portScanJob struct {
	host string
	port int
}

type portScanResult struct {
	host string
	port int
	open bool
}

// 修改：为PortScanner添加延迟控制字段
type PortScanner struct {
	targets          []string
	ports            []int
	logger           *controller.Logger       // 日志记录器
	timeout          time.Duration            // 连接超时时间
	progressCallback func(current, total int) // 进度回调函数
	delayType        controller.DelayType     // 延迟类型
	delayValue       int                      // 延迟基础值
}

// 修改：初始化时传入延迟配置
func NewPortScanner(targets []string, ports []int, logger *controller.Logger, timeout time.Duration) *PortScanner {
	if timeout == 0 {
		timeout = 5 * time.Second // 默认5秒超时
	}
	return &PortScanner{
		targets:    targets,
		ports:      ports,
		logger:     logger,
		timeout:    timeout,
		delayType:  controller.ConstantDelay, // 默认延迟类型
		delayValue: 100,                      // 默认延迟值
	}
}

// 新增：设置延迟配置
func (s *PortScanner) SetDelayConfig(delayType controller.DelayType, delayValue int) {
	s.delayType = delayType
	s.delayValue = delayValue
}

// 修改：worker函数，添加延迟控制
// 在worker函数中添加更详细的延迟日志
func (s *PortScanner) portScanWorker(id int, jobs <-chan portScanJob, results chan<- portScanResult) {
	step := 0
	for job := range jobs {
		delay := controller.GetDelay(s.delayType, s.delayValue, step)
		if delay > 0 {
			// 改进：更详细的延迟日志
			s.logger.Logf("端口扫描Worker %d: 步骤=%d, 延迟类型=%s, 延迟=%v, 目标=%s:%d",
				id, step, s.delayType, delay, job.host, job.port)
			time.Sleep(delay)
		}

		addr := net.JoinHostPort(job.host, fmt.Sprintf("%d", job.port))
		conn, err := net.DialTimeout("tcp", addr, s.timeout)
		if err == nil {
			s.logger.Logf("%s:%d 端口开放", job.host, job.port)
			conn.Close()
			results <- portScanResult{host: job.host, port: job.port, open: true}
		} else {
			s.logger.Logf("%s:%d 端口关闭或无法连接: %v", job.host, job.port, err)
			results <- portScanResult{host: job.host, port: job.port, open: false}
		}
		step++
	}
}

// SetProgressCallback 设置进度回调函数
func (s *PortScanner) SetProgressCallback(callback func(current, total int)) {
	s.progressCallback = callback
}

// Scan 扫描目标主机的TCP端口
func (s *PortScanner) Scan() (interface{}, error) {
	openPorts := make(map[string][]int)
	var mu sync.Mutex
	s.logger.Log("TCP端口扫描开始，待扫描主机: " + fmt.Sprintf("%v", s.targets))
	s.logger.Logf("待扫描端口列表: %v", s.ports)
	s.logger.Logf("延迟配置: 类型=%s, 值=%dms", s.delayType, s.delayValue)

	totalTasks := len(s.targets) * len(s.ports)
	jobs := make(chan portScanJob, totalTasks)
	results := make(chan portScanResult, totalTasks)

	// 启动worker（控制并发度）
	const maxWorkers = 50
	for w := 1; w <= maxWorkers; w++ {
		go s.portScanWorker(w, jobs, results)
	}

	// 分发任务
	go func() {
		for _, host := range s.targets {
			for _, port := range s.ports {
				jobs <- portScanJob{host: host, port: port}
			}
		}
		close(jobs)
	}()

	// 收集结果并更新进度
	completed := 0
	for i := 0; i < totalTasks; i++ {
		result := <-results
		if result.open {
			mu.Lock()
			openPorts[result.host] = append(openPorts[result.host], result.port)
			mu.Unlock()
		}
		completed++
		if s.progressCallback != nil {
			s.progressCallback(completed, totalTasks)
		}
	}

	s.logger.Log("TCP端口扫描结束")
	return openPorts, nil
}

// ScanHosts 并发扫描在线主机的TCP端口
// 在扫描结束时添加延迟统计
func (s *PortScanner) ScanHosts(aliveHosts []string) (interface{}, error) {
	openPorts := make(map[string][]int)
	var mu sync.Mutex
	s.logger.Log("TCP端口扫描开始，待扫描在线主机: " + fmt.Sprintf("%v", aliveHosts))
	s.logger.Logf("待扫描端口列表: %v", s.ports)
	s.logger.Logf("延迟配置: 类型=%s, 值=%dms", s.delayType, s.delayValue)

	totalTasks := len(aliveHosts) * len(s.ports)
	jobs := make(chan portScanJob, totalTasks)
	results := make(chan portScanResult, totalTasks)

	// 启动worker（控制并发度）
	const maxWorkers = 50
	for w := 1; w <= maxWorkers; w++ {
		go s.portScanWorker(w, jobs, results)
	}

	// 分发任务
	go func() {
		for _, host := range aliveHosts {
			for _, port := range s.ports {
				jobs <- portScanJob{host: host, port: port}
			}
		}
		close(jobs)
	}()

	// 收集结果并更新进度
	completed := 0
	for i := 0; i < totalTasks; i++ {
		result := <-results
		if result.open {
			mu.Lock()
			openPorts[result.host] = append(openPorts[result.host], result.port)
			mu.Unlock()
		}
		completed++
		if s.progressCallback != nil {
			s.progressCallback(completed, totalTasks)
		}
	}

	// 添加延迟统计
	totalDelay := time.Duration(0)
	if s.delayValue > 0 {
		totalTasks := len(aliveHosts) * len(s.ports)
		// 估算总延迟时间（简化计算）
		avgDelay := time.Duration(s.delayValue) * time.Millisecond
		totalDelay = avgDelay * time.Duration(totalTasks)
		s.logger.Logf("端口扫描延迟统计: 总任务数=%d, 平均延迟=%v, 估算总延迟=%v",
			totalTasks, avgDelay, totalDelay)
	}

	s.logger.Log("TCP端口扫描结束")
	return openPorts, nil
}

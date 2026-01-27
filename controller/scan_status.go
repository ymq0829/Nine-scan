package controller

import "sync"

// ScanStatusManager 管理扫描状态
type ScanStatusManager struct {
	currentScanMethod string
	mu                sync.RWMutex
}

// NewScanStatusManager 创建新的扫描状态管理器
func NewScanStatusManager() *ScanStatusManager {
	return &ScanStatusManager{
		currentScanMethod: "ICMP扫描", // 默认值
	}
}

// SetCurrentScanMethod 设置当前扫描方法
func (s *ScanStatusManager) SetCurrentScanMethod(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentScanMethod = method
}

// GetCurrentScanMethod 获取当前扫描方法
func (s *ScanStatusManager) GetCurrentScanMethod() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentScanMethod == "" {
		return "ICMP扫描" // 默认值
	}
	return s.currentScanMethod
}

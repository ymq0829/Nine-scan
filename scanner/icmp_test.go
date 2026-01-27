package scanner

import (
	"testing"
	"time"

	"example.com/project/controller"
)

func TestICMPScanner(t *testing.T) {
	// 创建测试logger
	logger := controller.NewLogger("test.log")

	// 测试本地回环地址
	targets := []string{"127.0.0.1"}
	scanner := NewICMPScanner(targets, logger)

	if scanner == nil {
		t.Error("Expected scanner instance, got nil")
	}

	// 测试Scan方法
	result, err := scanner.Scan()
	if err != nil {
		t.Errorf("Scan returned error: %v", err)
	}

	// 检查结果类型
	if hostInfos, ok := result.([]HostInfo); ok {
		t.Logf("Found %d alive hosts", len(hostInfos))
		for _, host := range hostInfos {
			t.Logf("Host: %s, Alive: %t, TTL: %d", host.Host, host.Alive, host.TTL)
		}
	} else {
		t.Errorf("Expected []HostInfo result, got %T", result)
	}
}

func TestICMPScannerWithMultipleTargets(t *testing.T) {
	logger := controller.NewLogger("test.log")

	// 测试多个目标
	targets := []string{"127.0.0.1", "192.168.1.1", "8.8.8.8"}
	scanner := NewICMPScanner(targets, logger)

	scanner.SetProgressCallback(func(current, total int) {
		t.Logf("Progress: %d/%d", current, total)
	})

	result, err := scanner.Scan()
	if err != nil {
		t.Errorf("Scan returned error: %v", err)
	}

	if hostInfos, ok := result.([]HostInfo); ok {
		t.Logf("Total alive hosts: %d", len(hostInfos))
	}
}

func TestSendEchoRequest(t *testing.T) {
	config := ICMPConfig{
		Timeout: 2 * time.Second,
		Retries: 2,
		Logger:  controller.NewLogger("test.log"),
	}

	// 测试单个ICMP请求
	alive, ttl, err := SendEchoRequest("127.0.0.1", config)
	if err != nil {
		t.Errorf("SendEchoRequest error: %v", err)
	}

	t.Logf("Host 127.0.0.1 - Alive: %t, TTL: %d", alive, ttl)
}

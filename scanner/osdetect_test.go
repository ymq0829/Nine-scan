package scanner

import (
	"testing"

	"example.com/project/controller"
)

func TestOSDetector(t *testing.T) {
	// 创建测试用的日志记录器
	logger := controller.NewLogger("test_osdetect.log")
	defer logger.Close()

	testCases := []struct {
		name     string
		hosts    []string
		expected map[string]string
	}{
		{
			"localhost",
			[]string{"127.0.0.1"},
			map[string]string{"127.0.0.1": "Windows (本地网络猜测)"},
		},
		{
			"google-dns",
			[]string{"8.8.8.8"},
			map[string]string{"8.8.8.8": "Linux/Unix (服务提供商猜测)"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 正确初始化OSDetector，传入logger
			detector := NewOSDetector(logger)
			result, err := detector.Detect(tc.hosts)
			if err != nil {
				t.Errorf("Detect returned error: %v", err)
			}

			osResult := result.(map[string]string)
			for host, os := range tc.expected {
				if osResult[host] != os {
					t.Errorf("Detect(%v)[%s] = %s, want %s",
						tc.hosts, host, osResult[host], os)
				}
			}
		})
	}
}

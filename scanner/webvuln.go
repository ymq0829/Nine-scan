// scanner/webvuln.go
package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"example.com/project/controller"
)

// WebVulnerability Web应用漏洞
type WebVulnerability struct {
	Path       string `json:"path"`
	Method     string `json:"method"`
	Parameter  string `json:"parameter"`
	CVE        string `json:"cve"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Payload    string `json:"payload"`
	Pattern    string `json:"pattern"`
	FixedIn    string `json:"fixed_in"`
	Confidence int    `json:"confidence"`
}

// WebVulnScanner Web应用漏洞扫描器
type WebVulnScanner struct {
	targets   map[string][]int              // key: 主机IP, value: 开放端口列表
	services  map[string]map[int]string     // key: 主机IP, value: map[端口]服务名
	timeout   time.Duration                 // 连接超时时间
	logger    *controller.Logger            // 日志记录器
	webVulnDB map[string][]WebVulnerability // Web漏洞数据库
}

// NewWebVulnScanner 初始化Web应用漏洞扫描器
func NewWebVulnScanner(openPorts map[string][]int, services map[string]map[int]string, logger *controller.Logger) *WebVulnScanner {
	scanner := &WebVulnScanner{
		targets:   openPorts,
		services:  services,
		timeout:   5 * time.Second,
		logger:    logger,
		webVulnDB: make(map[string][]WebVulnerability),
	}

	// 初始化Web漏洞数据库
	scanner.initializeWebVulnDatabase()

	return scanner
}

// initializeWebVulnDatabase 初始化Web漏洞数据库
func (s *WebVulnScanner) initializeWebVulnDatabase() {
	// 常见Web漏洞
	commonWebVulns := []WebVulnerability{
		{
			Path:       "/admin",
			Method:     "GET",
			Parameter:  "",
			Name:       "Admin Panel Exposure",
			Severity:   "High",
			Confidence: 70,
		},
		{
			Path:       "/login.php",
			Method:     "POST",
			Parameter:  "username",
			Payload:    "' OR '1'='1",
			Pattern:    "Welcome|Dashboard",
			Name:       "SQL Injection",
			Severity:   "Critical",
			Confidence: 90,
		},
		{
			Path:       "/wp-login.php",
			Method:     "GET",
			Parameter:  "",
			Name:       "WordPress Login Page",
			Severity:   "Medium",
			Confidence: 80,
		},
		{
			Path:       "/.git",
			Method:     "GET",
			Parameter:  "",
			Name:       "Git Repository Exposure",
			Severity:   "High",
			Confidence: 95,
		},
		{
			Path:       "/backup.zip",
			Method:     "GET",
			Parameter:  "",
			Name:       "Backup File Exposure",
			Severity:   "High",
			Confidence: 95,
		},
		{
			Path:       "/",
			Method:     "GET",
			Parameter:  "",
			Pattern:    "Apache/2\\.4\\.(49|50)",
			CVE:        "CVE-2021-41773",
			Name:       "Apache HTTP Server Path Traversal",
			Severity:   "High",
			Confidence: 90,
		},
	}

	s.webVulnDB["HTTP"] = commonWebVulns
	s.webVulnDB["HTTPS"] = commonWebVulns
}

// checkWebVulnerability 检查单个Web漏洞
func (s *WebVulnScanner) checkWebVulnerability(baseURL string, vuln WebVulnerability) bool {
	client := &http.Client{Timeout: s.timeout}

	fullURL := baseURL + vuln.Path

	switch vuln.Method {
	case "GET":
		if vuln.Parameter != "" && vuln.Payload != "" {
			// 添加参数到URL
			parsedURL, err := url.Parse(fullURL)
			if err == nil {
				q := parsedURL.Query()
				q.Add(vuln.Parameter, vuln.Payload)
				parsedURL.RawQuery = q.Encode()
				fullURL = parsedURL.String()
			}
		}

		resp, err := client.Get(fullURL)
		if err != nil {
			s.logger.Logf("GET请求失败: %s, 错误: %v", fullURL, err)
			return false
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		response := string(body)

		// 检查响应
		if vuln.Pattern != "" {
			re := regexp.MustCompile(vuln.Pattern)
			return re.MatchString(response)
		}

		// 检查状态码
		return resp.StatusCode == 200

	case "POST":
		if vuln.Parameter != "" && vuln.Payload != "" {
			data := url.Values{}
			data.Set(vuln.Parameter, vuln.Payload)

			resp, err := client.PostForm(fullURL, data)
			if err != nil {
				s.logger.Logf("POST请求失败: %s, 错误: %v", fullURL, err)
				return false
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			response := string(body)

			// 检查响应
			if vuln.Pattern != "" {
				re := regexp.MustCompile(vuln.Pattern)
				return re.MatchString(response)
			}

			// 检查状态码
			return resp.StatusCode == 200
		}

		return false

	default:
		return false
	}
}

// ScanWebVulnerabilities 扫描单个主机的Web漏洞
func (s *WebVulnScanner) ScanWebVulnerabilities(host string, port int) []WebVulnerability {
	var vulnerabilities []WebVulnerability

	// 检查是否是Web端口
	webPorts := []int{80, 443, 8080, 8081, 8443}
	isWebPort := false
	for _, p := range webPorts {
		if p == port {
			isWebPort = true
			break
		}
	}

	if !isWebPort {
		return vulnerabilities
	}

	// 确定协议
	protocol := "http"
	if port == 443 || port == 8443 {
		protocol = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", protocol, host, port)
	s.logger.Logf("开始扫描Web漏洞: %s", baseURL)

	// 获取适用的漏洞
	webVulns := s.webVulnDB["HTTP"]
	if protocol == "https" {
		webVulns = s.webVulnDB["HTTPS"]
	}

	// 扫描每个漏洞
	for _, vuln := range webVulns {
		if s.checkWebVulnerability(baseURL, vuln) {
			s.logger.Logf("发现Web漏洞: %s at %s%s", vuln.Name, baseURL, vuln.Path)
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// Scan 扫描所有主机的Web漏洞
func (s *WebVulnScanner) Scan() (interface{}, error) {
	webVulnResult := make(map[string]map[int][]WebVulnerability)
	s.logger.Log("Web应用漏洞扫描开始")

	var wg sync.WaitGroup
	var mu sync.Mutex

	// 遍历每个在线主机及其开放端口
	for host, ports := range s.targets {
		s.logger.Logf("开始扫描主机%s的Web漏洞，开放端口：%v", host, ports)

		// 扫描每个开放端口的Web漏洞
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()

				// 扫描Web漏洞
				vulns := s.ScanWebVulnerabilities(h, p)

				// 如果发现漏洞，添加到结果
				if len(vulns) > 0 {
					mu.Lock()
					if _, hostExists := webVulnResult[h]; !hostExists {
						webVulnResult[h] = make(map[int][]WebVulnerability)
					}
					webVulnResult[h][p] = vulns
					mu.Unlock()
				}
			}(host, port)
		}
	}

	wg.Wait()
	s.logger.Logf("Web应用漏洞扫描结束，共检测到%d个主机的Web漏洞", len(webVulnResult))
	return webVulnResult, nil
}

package scanner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"example.com/project/controller"
)

// OSV 漏洞数据结构 (GitHub Advisory Database 标准化格式)
type OSVVulnerability struct {
	SchemaVersion    string                 `json:"schema_version"`
	ID               string                 `json:"id"`
	Modified         string                 `json:"modified"`
	Published        string                 `json:"published"`
	Withdrawn        string                 `json:"withdrawn,omitempty"`
	Aliases          []string               `json:"aliases,omitempty"`
	Summary          string                 `json:"summary,omitempty"`
	Details          string                 `json:"details"`
	Severity         []OSVSeverity          `json:"severity,omitempty"`
	Affected         []OSVAffected          `json:"affected"`
	References       []OSVReference         `json:"references"`
	Credits          []OSVCredit            `json:"credits,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Package           OSVPackage             `json:"package"`
	Ranges            []OSVRange             `json:"ranges"`
	Versions          []string               `json:"versions,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl,omitempty"`
}

type OSVRange struct {
	Type   string          `json:"type"`
	Repo   string          `json:"repo,omitempty"`
	Events []OSVRangeEvent `json:"events"`
}

type OSVRangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Limit      string `json:"limit,omitempty"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OSVCredit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type"`
}

// 扫描结果结构
type VulnerabilityScanResult struct {
	Host            string                  `json:"host"`
	OS              string                  `json:"os"`
	OpenPorts       []int                   `json:"open_ports"`
	Services        []ServiceFingerprint    `json:"services"`
	Vulnerabilities []DetectedVulnerability `json:"vulnerabilities"`
	ScanTimestamp   time.Time               `json:"scan_timestamp"`
}

type DetectedVulnerability struct {
	VulnerabilityID string            `json:"vulnerability_id"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Severity        string            `json:"severity"`
	CVSSScore       float64           `json:"cvss_score,omitempty"`
	AffectedService string            `json:"affected_service"`
	AffectedVersion string            `json:"affected_version"`
	FixedVersion    string            `json:"fixed_version,omitempty"`
	References      []string          `json:"references"`
	Confidence      int               `json:"confidence"`
	Evidence        map[string]string `json:"evidence"`
	OSVData         *OSVVulnerability `json:"osv_data,omitempty"`
}

// 漏洞扫描器
type VulnerabilityScanner struct {
	Logger          *controller.Logger
	VulnerabilityDB []OSVVulnerability
	CacheDir        string
	CacheTTL        time.Duration
	mu              sync.RWMutex
}

// 创建漏洞扫描器
func NewVulnerabilityScanner(logger *controller.Logger) *VulnerabilityScanner {
	return &VulnerabilityScanner{
		Logger:   logger,
		CacheDir: filepath.Join(os.TempDir(), "vuln_scanner_cache"),
		CacheTTL: 24 * time.Hour,
	}
}

// 加载漏洞数据库
func (vs *VulnerabilityScanner) LoadVulnerabilityDB() error {
	vs.Logger.Log("开始加载漏洞数据库...")

	// 检查本地缓存
	if vs.loadFromCache() {
		vs.Logger.Log("从缓存加载漏洞数据库成功")
		return nil
	}

	// 从GitHub Advisory Database加载
	vs.Logger.Log("从GitHub Advisory Database加载漏洞数据...")

	// 使用OSV格式的GitHub Advisory API
	sources := []string{
		"https://api.osv.dev/v1/vulns?source=GitHub",
		// 可以添加其他OSV兼容的数据源
	}

	var allVulns []OSVVulnerability
	for _, source := range sources {
		vulns, err := vs.fetchFromSource(source)
		if err != nil {
			vs.Logger.Logf("从源 %s 加载失败: %v", source, err)
			continue
		}
		allVulns = append(allVulns, vulns...)
	}

	if len(allVulns) == 0 {
		return fmt.Errorf("无法从任何数据源加载漏洞数据")
	}

	vs.mu.Lock()
	vs.VulnerabilityDB = allVulns
	vs.mu.Unlock()

	// 保存到缓存
	vs.saveToCache()
	vs.Logger.Logf("成功加载 %d 个漏洞记录", len(allVulns))
	return nil
}

// 执行漏洞扫描
func (vs *VulnerabilityScanner) Scan(
	host string,
	osInfo string,
	openPorts []int,
	services []ServiceFingerprint,
	path string, // 新增路径参数
) (*VulnerabilityScanResult, error) {
	vs.Logger.Logf("开始对主机 %s 进行漏洞扫描", host)

	result := &VulnerabilityScanResult{
		Host:          host,
		OS:            osInfo,
		OpenPorts:     openPorts,
		Services:      services,
		ScanTimestamp: time.Now(),
	}

	// 基于操作系统检测漏洞
	osVulns := vs.scanOSVulnerabilities(host, osInfo)
	result.Vulnerabilities = append(result.Vulnerabilities, osVulns...)

	// 基于服务检测漏洞
	serviceVulns := vs.scanServiceVulnerabilities(host, services)
	result.Vulnerabilities = append(result.Vulnerabilities, serviceVulns...)

	vs.Logger.Logf("主机 %s 漏洞扫描完成，发现 %d 个潜在漏洞", host, len(result.Vulnerabilities))
	return result, nil
}

// 基于操作系统检测漏洞
func (vs *VulnerabilityScanner) scanOSVulnerabilities(host, osInfo string) []DetectedVulnerability {
	var vulnerabilities []DetectedVulnerability

	vs.mu.RLock()
	defer vs.mu.RUnlock()

	for _, vuln := range vs.VulnerabilityDB {
		if vs.matchOSVulnerability(vuln, osInfo) {
			detected := vs.convertToDetectedVulnerability(vuln, "操作系统", osInfo, "")
			detected.Evidence["检测方法"] = "操作系统版本匹配"
			detected.Evidence["操作系统"] = osInfo
			vulnerabilities = append(vulnerabilities, detected)
		}
	}

	return vulnerabilities
}

// 基于服务检测漏洞
func (vs *VulnerabilityScanner) scanServiceVulnerabilities(host string, services []ServiceFingerprint) []DetectedVulnerability {
	var vulnerabilities []DetectedVulnerability

	vs.mu.RLock()
	defer vs.mu.RUnlock()

	for _, service := range services {
		for _, vuln := range vs.VulnerabilityDB {
			if vs.matchServiceVulnerability(vuln, service) {
				detected := vs.convertToDetectedVulnerability(vuln, service.ServiceName, service.ServiceVersion, strconv.Itoa(service.Port))
				detected.Evidence["检测方法"] = "服务版本匹配"
				detected.Evidence["服务名称"] = service.ServiceName
				detected.Evidence["服务版本"] = service.ServiceVersion
				detected.Evidence["端口"] = strconv.Itoa(service.Port)
				vulnerabilities = append(vulnerabilities, detected)
			}
		}
	}

	return vulnerabilities
}

// 匹配操作系统漏洞
func (vs *VulnerabilityScanner) matchOSVulnerability(vuln OSVVulnerability, osInfo string) bool {
	osInfoLower := strings.ToLower(osInfo)

	// 1. 检查漏洞是否直接影响操作系统
	for _, affected := range vuln.Affected {
		if affected.Package.Ecosystem == "os" {
			osName := strings.ToLower(affected.Package.Name)
			if strings.Contains(osInfoLower, osName) {
				// 尝试提取版本
				version := extractOSVersion(osInfo, osName)
				// 如果提取到版本，则进行版本范围匹配
				if version != "" {
					if vs.matchVersion(version, affected.Ranges) {
						return true
					}
				} else {
					// 没有版本信息，则只匹配名称
					return true
				}
			}
		}
	}

	// 2. 特殊漏洞的显式匹配（如EternalBlue）
	if vs.isEternalBlueVulnerability(vuln, osInfo) {
		return true
	}

	return false
}

// 检测是否为EternalBlue漏洞（增强版，包含版本验证）
func (vs *VulnerabilityScanner) isEternalBlueVulnerability(vuln OSVVulnerability, osInfo string) bool {
	// EternalBlue的CVE ID和常见别名
	eternalBlueIDs := map[string]bool{
		"CVE-2017-0144": true,
		"MS17-010":      true,
	}

	isEternalBlue := false

	// 检查漏洞ID
	if _, exists := eternalBlueIDs[vuln.ID]; exists {
		isEternalBlue = true
	}

	// 检查别名
	if !isEternalBlue {
		for _, alias := range vuln.Aliases {
			if _, exists := eternalBlueIDs[alias]; exists {
				isEternalBlue = true
				break
			}
		}
	}

	// 检查描述中的关键词
	if !isEternalBlue && (strings.Contains(strings.ToLower(vuln.Summary), "eternalblue") ||
		strings.Contains(strings.ToLower(vuln.Details), "eternalblue")) {
		isEternalBlue = true
	}

	// 如果是EternalBlue漏洞，验证操作系统版本
	if isEternalBlue {
		// EternalBlue影响Windows 7/8.1/10 v1507-v1607/Server 2008 SP2/2012/2016
		version := extractOSVersion(osInfo, "windows")
		if version == "" {
			return false
		}

		// 检查Windows版本是否在受影响范围内
		if vs.compareWindowsVersions(version, "6.1") >= 0 && // Windows 7+
			vs.compareWindowsVersions(version, "10.0.15063") < 0 { // 早于Windows 10 v1703
			return true
		}
	}

	return false
}

// 匹配服务漏洞
func (vs *VulnerabilityScanner) matchServiceVulnerability(vuln OSVVulnerability, service ServiceFingerprint) bool {
	serviceNameLower := strings.ToLower(service.ServiceName)

	for _, affected := range vuln.Affected {
		packageNameLower := strings.ToLower(affected.Package.Name)

		// 1. 直接包名匹配
		if strings.Contains(serviceNameLower, packageNameLower) {
			if vs.matchVersion(service.ServiceVersion, affected.Ranges) {
				return true
			}
		}

		// 2. 服务类型匹配（如FTP/HTTP等）
		if affected.Package.Ecosystem == "service" {
			serviceType := strings.ToLower(strings.Split(serviceNameLower, " ")[0])
			if strings.Contains(packageNameLower, serviceType) {
				if vs.matchVersion(service.ServiceVersion, affected.Ranges) {
					return true
				}
			}
		}
	}
	return false
}

// 版本匹配逻辑（增强版，支持Windows版本范围）
func (vs *VulnerabilityScanner) matchVersion(version string, ranges []OSVRange) bool {
	if version == "" || version == "unknown" {
		return false
	}

	for _, r := range ranges {
		// 支持SEMVER和WINDOWS版本类型
		if r.Type == "SEMVER" || r.Type == "WINDOWS" {
			for _, event := range r.Events {
				if event.Introduced != "" && vs.compareVersions(version, event.Introduced) >= 0 {
					if event.Fixed == "" || vs.compareVersions(version, event.Fixed) < 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

// 增强版本比较（支持Windows版本和语义化版本）
func (vs *VulnerabilityScanner) compareVersions(v1, v2 string) int {
	// 处理Windows版本格式 (e.g., 10.0.19044)
	if strings.Contains(v1, "windows") || strings.Contains(v2, "windows") {
		return vs.compareWindowsVersions(v1, v2)
	}

	// 标准语义化版本比较
	return vs.compareSemanticVersions(v1, v2)
}

// 比较Windows版本
func (vs *VulnerabilityScanner) compareWindowsVersions(v1, v2 string) int {
	// 提取纯数字版本
	extractNumbers := func(v string) []int {
		parts := strings.Split(v, ".")
		var nums []int
		for _, p := range parts {
			if num, err := strconv.Atoi(p); err == nil {
				nums = append(nums, num)
			}
		}
		return nums
	}

	v1Nums := extractNumbers(v1)
	v2Nums := extractNumbers(v2)

	for i := 0; i < len(v1Nums) && i < len(v2Nums); i++ {
		if v1Nums[i] < v2Nums[i] {
			return -1
		} else if v1Nums[i] > v2Nums[i] {
			return 1
		}
	}

	if len(v1Nums) < len(v2Nums) {
		return -1
	} else if len(v1Nums) > len(v2Nums) {
		return 1
	}

	return 0
}

// 从操作系统信息字符串中提取版本号
func extractOSVersion(osInfo, osName string) string {
	osInfoLower := strings.ToLower(osInfo)
	osNameLower := strings.ToLower(osName)

	// Windows版本提取
	if strings.Contains(osNameLower, "windows") {
		// 匹配类似 "Windows 10.0.19044" 的版本模式
		re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
		matches := re.FindStringSubmatch(osInfo)
		if len(matches) > 0 {
			return matches[0]
		}

		// 匹配简化版本如 "Windows 10"
		re = regexp.MustCompile(`windows\s+(\d+)`)
		matches = re.FindStringSubmatch(osInfoLower)
		if len(matches) > 1 {
			return matches[1] + ".0.0"
		}
	}
	return ""
}

// 比较语义化版本
func (vs *VulnerabilityScanner) compareSemanticVersions(v1, v2 string) int {
	// 移除版本前缀
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	// 分割主/次/修订号
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var part1, part2 int

		if i < len(v1Parts) {
			part1, _ = strconv.Atoi(v1Parts[i])
		}

		if i < len(v2Parts) {
			part2, _ = strconv.Atoi(v2Parts[i])
		}

		if part1 < part2 {
			return -1
		} else if part1 > part2 {
			return 1
		}
	}

	return 0
}

// 转换OSV漏洞为检测结果
func (vs *VulnerabilityScanner) convertToDetectedVulnerability(
	vuln OSVVulnerability,
	serviceName string,
	serviceVersion string,
	port string,
) DetectedVulnerability {
	detected := DetectedVulnerability{
		VulnerabilityID: vuln.ID,
		Title:           vuln.Summary,
		Description:     vuln.Details,
		AffectedService: serviceName,
		AffectedVersion: serviceVersion,
		Confidence:      85,
		Evidence:        make(map[string]string),
		OSVData:         &vuln,
	}

	// 提取严重程度
	if len(vuln.Severity) > 0 {
		detected.Severity = vuln.Severity[0].Type
		if score, err := strconv.ParseFloat(vuln.Severity[0].Score, 64); err == nil {
			detected.CVSSScore = score
		}
	}

	// 提取参考链接
	for _, ref := range vuln.References {
		detected.References = append(detected.References, ref.URL)
	}

	// 尝试提取修复版本
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					detected.FixedVersion = event.Fixed
					break
				}
			}
		}
	}

	if port != "" {
		detected.Evidence["端口"] = port
	}

	return detected
}

// 缓存相关方法
func (vs *VulnerabilityScanner) loadFromCache() bool {
	cacheFile := filepath.Join(vs.CacheDir, "vulnerability_db.json")

	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return false
	}

	fileInfo, err := os.Stat(cacheFile)
	if err != nil {
		return false
	}

	// 检查缓存是否过期
	if time.Since(fileInfo.ModTime()) > vs.CacheTTL {
		return false
	}

	data, err := ioutil.ReadFile(cacheFile)
	if err != nil {
		return false
	}

	var vulns []OSVVulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		return false
	}

	vs.mu.Lock()
	vs.VulnerabilityDB = vulns
	vs.mu.Unlock()

	return true
}

func (vs *VulnerabilityScanner) saveToCache() {
	os.MkdirAll(vs.CacheDir, 0755)
	cacheFile := filepath.Join(vs.CacheDir, "vulnerability_db.json")

	vs.mu.RLock()
	data, err := json.Marshal(vs.VulnerabilityDB)
	vs.mu.RUnlock()

	if err != nil {
		vs.Logger.Logf("缓存保存失败: %v", err)
		return
	}

	if err := ioutil.WriteFile(cacheFile, data, 0644); err != nil {
		vs.Logger.Logf("缓存写入失败: %v", err)
	}
}

// 从数据源获取漏洞数据
func (vs *VulnerabilityScanner) fetchFromSource(source string) ([]OSVVulnerability, error) {
	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 创建请求
	req, err := http.NewRequest("GET", source, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Nine-Scan-Vulnerability-Scanner")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API返回非200状态码: %d", resp.StatusCode)
	}

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}

	// 解析JSON响应
	var osvResp struct {
		Vulns []OSVVulnerability `json:"vulns"`
	}
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return osvResp.Vulns, nil
}

// 批量扫描多个主机
func (vs *VulnerabilityScanner) BatchScan(
	hosts []string,
	osInfoMap map[string]string,
	openPortsMap map[string][]int,
	servicesMap map[string][]ServiceFingerprint,
) (map[string]*VulnerabilityScanResult, error) {
	results := make(map[string]*VulnerabilityScanResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()

			osInfo := osInfoMap[h]
			openPorts := openPortsMap[h]
			services := servicesMap[h]

			result, err := vs.Scan(h, osInfo, openPorts, services, "")
			if err != nil {
				vs.Logger.Logf("主机 %s 扫描失败: %v", h, err)
				return
			}

			mu.Lock()
			results[h] = result
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results, nil
}

// 生成扫描报告
func (vs *VulnerabilityScanner) GenerateReport(results map[string]*VulnerabilityScanResult) string {
	report := "漏洞扫描报告\n"
	report += "=" + strings.Repeat("=", 50) + "\n\n"

	totalVulns := 0
	for host, result := range results {
		report += fmt.Sprintf("主机: %s\n", host)
		report += fmt.Sprintf("操作系统: %s\n", result.OS)
		report += fmt.Sprintf("开放端口: %v\n", result.OpenPorts)
		report += fmt.Sprintf("发现漏洞: %d 个\n\n", len(result.Vulnerabilities))

		totalVulns += len(result.Vulnerabilities)

		for i, vuln := range result.Vulnerabilities {
			report += fmt.Sprintf("%d. %s (ID: %s)\n", i+1, vuln.Title, vuln.VulnerabilityID)
			report += fmt.Sprintf("   严重程度: %s", vuln.Severity)
			if vuln.CVSSScore > 0 {
				report += fmt.Sprintf(" (CVSS: %.1f)", vuln.CVSSScore)
			}
			report += "\n"
			report += fmt.Sprintf("   影响服务: %s %s\n", vuln.AffectedService, vuln.AffectedVersion)
			report += fmt.Sprintf("   置信度: %d%%\n", vuln.Confidence)
			report += "\n"
		}
		report += "\n"
	}

	report += fmt.Sprintf("总计扫描主机: %d 台\n", len(results))
	report += fmt.Sprintf("总计发现漏洞: %d 个\n", totalVulns)

	return report
}

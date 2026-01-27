# Nine-scan 网络扫描工具的 AI 编程助手指导

## 项目概述
Nine-scan 是一个基于 Go 的网络安全扫描工具，能够执行主机发现、端口扫描、服务识别和操作系统检测。它支持命令行和交互模式，并具有可配置的延迟算法以避免检测。

## 架构
- **main.go**：入口点，处理 CLI/交互模式，编排扫描管道
- **controller/**：输入解析、日志记录（`NewLogger`）、延迟控制（`DelayType`：constant/random/function1-4）、任务调度
- **scanner/**：核心扫描逻辑 - ICMP/TCP 主机发现、TCP 端口扫描、服务 banner 抓取、基于 TTL 的操作系统检测
- **output/**：结果聚合和文件输出（`scan_result.txt`）
- **ui/**：交互式菜单系统

## 关键工作流程
- **构建**：`go build -o project.exe main.go manifest_windows.go`
- **运行**：需要管理员权限进行 ICMP；Windows 上自动提升 UAC
- **扫描管道**：ICMP→PortScan→ServiceID→OSDetect→Output
- **延迟控制**：使用 `controller.NewScheduler()` 与延迟类型进行隐秘扫描
- **日志记录**：早期初始化 `controller.NewLogger("scan.log")`，使用 `logger.Logf()` 进行结构化输出

## 约定
- **接口**：所有扫描器实现 `Scanner.Scan() (interface{}, error)`
- **结果**：使用 `interface{}` 返回类型并进行类型断言（例如，`ScanResult{Hosts, ScanMethod}`）
- **并发**：端口扫描使用工作池（最大 50 个 goroutine）
- **错误处理**：记录错误但继续扫描；返回部分结果
- **Windows 特定**：`scanner/icmp.go` 中的原始套接字 ICMP 需要管理员权限；回退到 TCP 扫描
- **依赖**：最小化 - 仅 `golang.org/x/net`、`golang.org/x/sys`

## 示例
- **主机发现**：`icmpScanner := scanner.NewICMPScanner(targets, logger); result, _ := icmpScanner.Scan()`
- **端口扫描**：`portScanner := scanner.NewPortScanner(targets, ports, logger, timeout); portScanner.SetDelayConfig(delayType, delayVal)`
- **服务识别**：`serviceScanner := scanner.NewServiceScanner(openPorts, logger); services, _ := serviceScanner.Scan()`
- **操作系统检测**：`osDetector.DetectWithTTL([]HostInfo{...})` 使用 ICMP 响应中的 TTL

## 常见模式
- **调度器使用**：用 `scheduler.Schedule(func() interface{} { return scanner.Scan() })` 包装扫描调用
- **进度回调**：设置 `scanner.SetProgressCallback(func(current, total int) { ... })`
- **结果处理**：将 `interface{}` 断言为具体类型，如端口的 `map[string][]int`
- **目标解析**：在 `controller.ParseInput()` 中支持 IP/端口的 CIDR 范围</content>
<parameter name="filePath">d:\yabc\study\25秋\开发\code1.5\code1.2\.github\copilot-instructions.md
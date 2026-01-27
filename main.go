package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"example.com/project/controller"
	"example.com/project/output"
	"example.com/project/scanner"
	"example.com/project/ui"
)

type Scanner interface {
	Scan() (interface{}, error)
}

// 显示简单欢迎信息
func showSimpleWelcome() {
	fmt.Println("=====================================================")
	fmt.Println("             网络安全扫描工具 v1.0")
	fmt.Println("=====================================================")
	fmt.Println()
}

// 显示完整帮助信息
func showFullHelp() {
	fmt.Println("=====================================================")
	fmt.Println("             网络安全扫描工具 v1.0")
	fmt.Println("=====================================================")
	fmt.Println("功能特性:")
	fmt.Println("  • 主机存活性探测 (ICMP/TCP)")
	fmt.Println("  • TCP端口扫描")
	fmt.Println("  • 服务识别和Banner抓取")
	fmt.Println("  • 操作系统检测")
	fmt.Println("  • 多种延迟控制算法")
	fmt.Println("  • 详细的日志记录")
	fmt.Println("  • 交互式用户界面")
	fmt.Println()
	fmt.Println("使用模式:")
	fmt.Println("  1. 命令行模式: 直接使用命令行参数")
	fmt.Println("  2. 交互模式: 不提供参数或使用 -i 参数")
	fmt.Println()
	fmt.Println("使用示例:")
	fmt.Println("  命令行模式:")
	fmt.Println("    project.exe -targets \"192.168.1.1-254\" -ports \"21-23,80,443\"")
	fmt.Println("    project.exe -targets \"192.168.1.1\" -delay random -delayVal 200")
	fmt.Println("  交互模式:")
	fmt.Println("    project.exe")
	fmt.Println("    project.exe -i")
	fmt.Println()
	fmt.Println("参数说明:")
	fmt.Println("  -targets: 目标主机(IP范围或逗号分隔)")
	fmt.Println("  -ports: 扫描端口(范围或逗号分隔)")
	fmt.Println("  -delay: 延迟类型(constant/random/function1-4)")
	fmt.Println("  -delayVal: 延迟基础值(毫秒)")
	fmt.Println("  -timeout: 连接超时时间(秒)")
	fmt.Println("  -i, --interactive: 启用交互模式")
	fmt.Println("=====================================================")
	fmt.Println()
}

// 检查是否需要显示帮助信息
func shouldShowHelp() bool {
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			return true
		}
	}
	return false
}

// 检查是否启用交互模式
func shouldUseInteractiveMode() bool {
	if len(os.Args) == 1 {
		return true // 没有参数时默认使用交互模式
	}
	for _, arg := range os.Args[1:] {
		if arg == "-i" || arg == "--interactive" {
			return true
		}
	}
	return false
}

// 显示帮助信息并退出
func showHelpAndExit() {
	showFullHelp()
	fmt.Println("使用 -h 或 --help 查看此帮助信息")
	fmt.Println("直接运行程序（不提供参数）将进入交互模式")
	os.Exit(0)
}

// 询问用户是否继续提权
func askForElevation() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("是否继续并请求管理员权限？(y/n): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

// 在main函数中优化扫描流程
func main() {
	// 检查是否需要显示帮助信息
	if shouldShowHelp() {
		showFullHelp()
		os.Exit(0)
	}

	// 检查是否启用交互模式
	if shouldUseInteractiveMode() {
		runInteractiveMode()
	} else {
		runCommandLineMode()
	}
}

// runInteractiveMode 运行交互模式
func runInteractiveMode() {
	// 检查是否已经具有管理员权限
	if !IsAdmin() {
		fmt.Println("需要管理员权限运行此程序以获得最佳扫描效果")
		fmt.Println("ICMP扫描功能需要管理员权限，否则将使用TCP扫描作为后备")
		fmt.Println()

		// 询问用户是否继续提权
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("是否继续并请求管理员权限？(y/n): ")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer == "y" || answer == "yes" {
			fmt.Println("正在请求UAC提权...")
			fmt.Println("请在新窗口中确认UAC提权请求")

			if RequestUACElevation() {
				// UAC提权成功，原进程会退出，新进程会重新启动
				// 等待一段时间让用户看到提示信息
				time.Sleep(2 * time.Second)
				return
			} else {
				fmt.Println("UAC提权失败，程序将继续以普通权限运行")
				fmt.Println("注意：ICMP扫描功能可能受限，将使用TCP扫描作为后备")
			}
		} else {
			fmt.Println("用户取消提权，程序将继续以普通权限运行")
			fmt.Println("注意：ICMP扫描功能可能受限")
		}
	} else {
		fmt.Println("当前以管理员权限运行")
	}

	ui := ui.NewInteractiveUI()
	ui.ShowWelcome()

	for {
		choice := ui.ShowMainMenu()

		switch choice {
		case 1: // 快速扫描
			ui.ClearScreen()
			ui.ShowWelcome()
			fmt.Println("=== 快速扫描模式 ===")
			quickScanParams := &controller.ScanParams{
				Targets:    []string{"127.0.0.1"},
				Ports:      []int{21, 22, 23, 80, 443, 3389, 3306, 8080},
				DelayType:  controller.ConstantDelay,
				DelayValue: 100,
				Timeout:    5,
			}
			fmt.Printf("使用默认参数: 目标=%v, 端口=%v, 延迟=%s\n",
				quickScanParams.Targets, quickScanParams.Ports, quickScanParams.DelayType)
			performScan(quickScanParams, ui)

		case 2: // 自定义扫描
			ui.ClearScreen()
			ui.ShowWelcome()
			params := ui.GetScanParameters()
			performScan(params, ui)

		case 3: // 查看帮助
			ui.ClearScreen()
			ui.ShowWelcome()
			ui.ShowHelp()
			ui.WaitForEnter()
			ui.ClearScreen()
			ui.ShowWelcome()

		case 4: // 退出程序
			fmt.Println("感谢使用网络安全扫描工具，再见！")
			os.Exit(0)
		}

		if !ui.AskForContinue() {
			fmt.Println("感谢使用网络安全扫描工具，再见！")
			break
		}
		ui.ClearScreen()
		ui.ShowWelcome()
	}
}

// runCommandLineMode 运行命令行模式
// 修复命令行模式中的错误
func runCommandLineMode() {
	// 检查是否已经具有管理员权限
	if !IsAdmin() {
		fmt.Println("需要管理员权限运行此程序以获得最佳扫描效果")
		fmt.Println("ICMP扫描功能需要管理员权限，否则将使用TCP扫描作为后备")
		fmt.Println()

		// 询问用户是否继续提权
		if !askForElevation() {
			fmt.Println("用户取消提权，程序将继续以普通权限运行")
			fmt.Println("注意：ICMP扫描功能可能受限")
		} else {
			fmt.Println("正在请求UAC提权...")
			fmt.Println("请在新窗口中确认UAC提权请求")

			if RequestUACElevation() {
				// UAC提权成功，原进程会重新启动
				// 等待一段时间让用户看到提示信息
				time.Sleep(2 * time.Second)
				return
			} else {
				fmt.Println("UAC提权失败，程序将继续以普通权限运行")
				fmt.Println("注意：ICMP扫描功能可能受限，将使用TCP扫描作为后备")
			}
		}
	} else {
		fmt.Println("当前以管理员权限运行")
	}

	fmt.Println("程序开始运行（命令行模式）")
	fmt.Println("Debug: Current process ID:", os.Getpid())

	// 1. 处理用户输入
	params, err := controller.ParseInput()
	if err != nil {
		fmt.Printf("参数错误: %v\n", err)
		os.Exit(1)
	}

	// 2. 初始化日志
	logger := controller.NewLogger("scan.log")
	defer logger.Close()
	logger.Log("程序启动，开始执行网络安全扫描任务")
	logger.Logf("用户输入参数: %v", params)

	// 3. 初始化扫描器（传入日志器）
	icmpScanner := scanner.NewICMPScanner(params.Targets, logger)
	portScanner := scanner.NewPortScanner(params.Targets, params.Ports, logger, time.Duration(params.Timeout)*time.Second)
	osDetector := scanner.NewOSDetector(logger)

	// 4. 初始化调度器（含延迟控制）
	scheduler := controller.NewScheduler(
		params.DelayType,
		params.DelayValue,
		logger,
	)

	// 5. 使用调度器执行扫描任务
	fmt.Println("开始ICMP扫描...")
	hosts := scheduler.Schedule(func() interface{} {
		icmpScanner.SetProgressCallback(func(current, total int) {
			progress := (float64(current) / float64(total)) * 100
			if progress > 100 {
				progress = 100
			}
			fmt.Printf("\rICMP扫描进度: %.1f%% (%d/%d)", progress, current, total)
		})
		result, _ := icmpScanner.Scan()
		return result
	})

	// 处理扫描结果，获取包含TTL值的HostInfo
	var aliveHosts []scanner.HostInfo
	var aliveHostStrings []string
	if hostInfos, ok := hosts.([]scanner.HostInfo); ok {
		aliveHosts = hostInfos
		// 转换为字符串切片
		for _, hostInfo := range aliveHosts {
			aliveHostStrings = append(aliveHostStrings, hostInfo.Host)
		}
		fmt.Printf("\nICMP扫描完成，发现 %d 个存活主机\n", len(aliveHosts))

		// 打印TTL信息用于调试
		for _, hostInfo := range aliveHosts {
			if hostInfo.TTL > 0 {
				fmt.Printf("主机 %s TTL: %d\n", hostInfo.Host, hostInfo.TTL)
			}
		}
	} else {
		// 兼容旧版本
		if strHosts, ok := hosts.([]string); ok {
			for _, host := range strHosts {
				aliveHosts = append(aliveHosts, scanner.HostInfo{
					Host:  host,
					Alive: true,
					TTL:   0, // 旧版本无法获取TTL
				})
				aliveHostStrings = append(aliveHostStrings, host)
			}
		}
		fmt.Printf("\nICMP扫描完成，发现 %d 个存活主机（使用兼容模式）\n", len(aliveHosts))
	}

	// 2. 端口扫描
	totalPortTasks := len(aliveHostStrings) * len(params.Ports)
	fmt.Printf("端口扫描进度: 0/%d\n", totalPortTasks)

	ports := scheduler.Schedule(func() interface{} {
		result, _ := portScanner.ScanHosts(aliveHostStrings)
		return result
	})
	openPorts, ok := ports.(map[string][]int)
	if !ok {
		logger.Errorf("端口扫描结果类型断言失败")
		fmt.Println("端口扫描结果处理失败")
		return
	}

	fmt.Printf("端口扫描进度: %d/%d\n", totalPortTasks, totalPortTasks)

	// 3. 服务扫描
	fmt.Println("服务识别: 进行中...")

	serviceScanner := scanner.NewServiceScanner(openPorts, logger)
	services := scheduler.Schedule(func() interface{} {
		result, _ := serviceScanner.Scan()
		return result
	})
	serviceInfo, ok := services.(map[string]map[int]string)
	if !ok {
		logger.Errorf("服务扫描结果类型断言失败")
		serviceInfo = make(map[string]map[int]string)
	}

	fmt.Println("服务识别: 完成")

	// 4. 操作系统识别
	fmt.Println("开始操作系统检测...")
	osResults, err := osDetector.DetectWithTTL(aliveHosts)
	if err != nil {
		logger.Log(fmt.Sprintf("操作系统检测失败: %v", err))
		return
	}

	// 类型断言：将 interface{} 转换为 map[string]string
	osInfo, ok := osResults.(map[string]string)
	if !ok {
		logger.Log("操作系统检测结果类型断言失败")
		osInfo = make(map[string]string)
	}

	// 打印操作系统检测结果
	for host, osType := range osInfo {
		fmt.Printf("主机 %s 操作系统: %s\n", host, osType)
	}

	if len(aliveHostStrings) == 0 {
		fmt.Println("没有发现存活主机，扫描结束")
		return
	}

	// 5. SMB/UDP扫描（如果启用）
	var smbUDPInfo interface{}
	if params.EnableSMB || params.EnableUDP {
		fmt.Println("SMB/UDP扫描: 进行中...")

		smbUDPConfig := &scanner.SMBUDPConfig{
			Targets:   aliveHostStrings,
			Ports:     params.Ports,
			Timeout:   time.Duration(params.Timeout) * time.Second,
			Logger:    logger,
			EnableSMB: params.EnableSMB,
			EnableUDP: params.EnableUDP,
		}
		smbUDPDetector := scanner.NewSMBUDPDetector(smbUDPConfig)

		smbUDPInfo, err = smbUDPDetector.Scan()
		if err != nil {
			logger.Errorf("SMB/UDP扫描失败: %v", err)
			smbUDPInfo = make(map[string]interface{})
		}

		fmt.Println("SMB/UDP扫描: 完成")
	}

	// 6. 显示结果
	result := output.NewResult(aliveHostStrings, openPorts, osInfo, serviceInfo)
	if smbUDPInfo != nil {
		result.SetSMBUDPInfo(smbUDPInfo)
	}

	// 在命令行模式下直接打印结果
	fmt.Println("\n=== 扫描结果 ===")
	result.Print()

	// 7. 保存结果
	if err := result.SaveToFile("scan_result.txt"); err != nil {
		logger.Errorf("扫描结果保存失败: %v", err)
		fmt.Printf("扫描结果保存失败: %v\n", err)
	} else {
		fmt.Println("扫描结果已保存到 scan_result.txt")
	}

	fmt.Println("\n扫描完成！")
}

// performScan 执行扫描任务（交互模式）
func performScan(params *controller.ScanParams, ui *ui.InteractiveUI) {
	// 初始化日志
	logger := controller.NewLogger("scan.log")
	defer logger.Close()
	logger.Log("程序启动，开始执行网络安全扫描任务")
	logger.Logf("用户输入参数: %v", params)

	// 初始化扫描器
	icmpScanner := scanner.NewICMPScanner(params.Targets, logger)
	portScanner := scanner.NewPortScanner(params.Targets, params.Ports, logger, time.Duration(params.Timeout)*time.Second)
	osDetector := scanner.NewOSDetector(logger)

	// 新增：初始化调度器（与命令行模式保持一致）
	scheduler := controller.NewScheduler(
		params.DelayType,
		params.DelayValue,
		logger,
	)

	// 新增：为端口扫描器设置延迟配置
	portScanner.SetDelayConfig(params.DelayType, params.DelayValue)

	// 将scanner.HostInfo转换为字符串切片用于端口扫描
	var aliveHostStrings []string

	// 1. 主机存活性探测（使用调度器）
	ui.ShowScanProgress("ICMP扫描", 0, len(params.Targets))
	hosts := scheduler.Schedule(func() interface{} {
		result, err := icmpScanner.Scan()
		if err != nil {
			logger.Log(fmt.Sprintf("ICMP扫描失败: %v", err))
			return []scanner.HostInfo{}
		}
		return result
	})

	// 处理扫描结果
	var aliveHosts []scanner.HostInfo
	if hostInfos, ok := hosts.([]scanner.HostInfo); ok {
		aliveHosts = hostInfos
		// 转换为字符串切片
		for _, hostInfo := range aliveHosts {
			aliveHostStrings = append(aliveHostStrings, hostInfo.Host)
		}
		ui.ShowScanProgress("ICMP扫描", len(aliveHosts), len(params.Targets))
		fmt.Printf("\nICMP扫描完成，发现 %d 个存活主机\n", len(aliveHosts))
	} else {
		// 兼容旧版本
		if strHosts, ok := hosts.([]string); ok {
			for _, host := range strHosts {
				aliveHosts = append(aliveHosts, scanner.HostInfo{
					Host:  host,
					Alive: true,
					TTL:   0,
				})
				aliveHostStrings = append(aliveHostStrings, host)
			}
		}
		ui.ShowScanProgress("ICMP扫描", len(aliveHosts), len(params.Targets))
		fmt.Printf("\nICMP扫描完成，发现 %d 个存活主机（使用兼容模式）\n", len(aliveHosts))
	}

	if len(aliveHosts) == 0 {
		fmt.Println("没有发现存活主机，扫描结束")
		return
	}

	// 2. 端口扫描（使用调度器）
	totalPortTasks := len(aliveHostStrings) * len(params.Ports)
	ui.ShowScanProgress("端口扫描", 0, totalPortTasks)

	ports := scheduler.Schedule(func() interface{} {
		result, err := portScanner.ScanHosts(aliveHostStrings)
		if err != nil {
			logger.Errorf("端口扫描失败: %v", err)
			return make(map[string][]int)
		}
		return result
	})
	openPorts, ok := ports.(map[string][]int)
	if !ok {
		logger.Errorf("端口扫描结果类型断言失败")
		fmt.Println("端口扫描结果处理失败")
		return
	}

	ui.ShowScanProgress("端口扫描", totalPortTasks, totalPortTasks)

	// 3. 服务扫描（使用调度器）
	ui.ShowScanProgress("服务识别", 0, 0)

	serviceScanner := scanner.NewServiceScanner(openPorts, logger)
	services := scheduler.Schedule(func() interface{} {
		result, err := serviceScanner.Scan()
		if err != nil {
			logger.Errorf("服务扫描失败: %v", err)
			return make(map[string]map[int]string)
		}
		return result
	})
	serviceInfo, ok := services.(map[string]map[int]string)
	if !ok {
		logger.Errorf("服务扫描结果类型断言失败")
		serviceInfo = make(map[string]map[int]string)
	}

	ui.ShowScanProgress("服务识别", 1, 1)

	// 4. 操作系统识别（使用调度器）
	ui.ShowScanProgress("操作系统检测", 0, 0)
	osResults := scheduler.Schedule(func() interface{} {
		result, err := osDetector.DetectWithTTL(aliveHosts)
		if err != nil {
			logger.Errorf("操作系统检测失败: %v", err)
			return make(map[string]string)
		}
		return result
	})
	osInfo, ok := osResults.(map[string]string)
	if !ok {
		logger.Errorf("操作系统检测结果类型断言失败")
		osInfo = make(map[string]string)
	}
	ui.ShowScanProgress("操作系统检测", 1, 1)

	// 5. SMB/UDP扫描（如果启用，使用调度器）
	var smbUDPInfo interface{}
	if params.EnableSMB || params.EnableUDP {
		ui.ShowScanProgress("SMB/UDP扫描", 0, 0)

		smbUDPConfig := &scanner.SMBUDPConfig{
			Targets:   aliveHostStrings,
			Ports:     params.Ports,
			Timeout:   time.Duration(params.Timeout) * time.Second,
			Logger:    logger,
			EnableSMB: params.EnableSMB,
			EnableUDP: params.EnableUDP,
		}
		smbUDPDetector := scanner.NewSMBUDPDetector(smbUDPConfig)

		smbUDPInfo = scheduler.Schedule(func() interface{} {
			result, err := smbUDPDetector.Scan()
			if err != nil {
				logger.Errorf("SMB/UDP扫描失败: %v", err)
				return make(map[string]interface{})
			}
			return result
		})

		ui.ShowScanProgress("SMB/UDP扫描", 1, 1)
	}

	// 6. 显示结果
	result := output.NewResult(aliveHostStrings, openPorts, osInfo, serviceInfo)
	if smbUDPInfo != nil {
		result.SetSMBUDPInfo(smbUDPInfo)
	}
	ui.ShowScanResult(result)

	// 7. 保存结果
	if err := result.SaveToFile("scan_result.txt"); err != nil {
		logger.Errorf("扫描结果保存失败: %v", err)
		fmt.Printf("扫描结果保存失败: %v\n", err)
	} else {
		fmt.Println("扫描结果已保存到 scan_result.txt")
	}

	fmt.Println("\n扫描完成！")
}

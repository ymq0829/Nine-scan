package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"example.com/project/controller"
	"example.com/project/output"
)

// InteractiveUI 交互式用户界面
type InteractiveUI struct {
	reader *bufio.Reader
}

// NewInteractiveUI 创建新的交互式界面
func NewInteractiveUI() *InteractiveUI {
	return &InteractiveUI{
		reader: bufio.NewReader(os.Stdin),
	}
}

// ShowWelcome 显示欢迎界面
func (ui *InteractiveUI) ShowWelcome() {
	fmt.Println("=====================================================")
	fmt.Println("             网络安全扫描工具 v1.0 - 交互模式")
	fmt.Println("=====================================================")
	fmt.Println()
}

// ShowMainMenu 显示主菜单
func (ui *InteractiveUI) ShowMainMenu() int {
	fmt.Println("请选择操作:")
	fmt.Println("1. 快速扫描（默认参数）")
	fmt.Println("2. 自定义扫描")
	fmt.Println("3. 查看帮助")
	fmt.Println("4. 退出程序")
	fmt.Print("请输入选择 (1-4): ")

	choice, err := ui.readInputInt()
	if err != nil || choice < 1 || choice > 4 {
		fmt.Println("无效选择，请重新输入")
		return ui.ShowMainMenu()
	}
	return choice
}

// GetScanParameters 获取扫描参数
func (ui *InteractiveUI) GetScanParameters() *controller.ScanParams {
	fmt.Println("\n=== 扫描参数配置 ===")

	// 获取目标主机
	targets := ui.getTargets()

	// 获取端口列表
	ports := ui.getPorts()

	// 获取延迟配置
	delayType, delayVal := ui.getDelayConfig()

	// 获取超时时间
	timeout := ui.getTimeout()

	// 获取SMB/UDP配置
	enableSMB, enableUDP := ui.getSMBUDPConfig()

	return &controller.ScanParams{
		Targets:    targets,
		Ports:      ports,
		DelayType:  delayType,
		DelayValue: delayVal,
		Timeout:    timeout,
		EnableSMB:  enableSMB,
		EnableUDP:  enableUDP,
	}
}

// getTargets 获取目标主机列表
func (ui *InteractiveUI) getTargets() []string {
	fmt.Print("请输入目标主机 (支持IP、网段、逗号分隔，如 192.168.1.1,192.168.1.1-254): ")
	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		fmt.Println("使用默认目标: 127.0.0.1")
		return []string{"127.0.0.1"}
	}

	targets := strings.Split(input, ",")
	return targets
}

// getPorts 获取端口列表
func (ui *InteractiveUI) getPorts() []int {
	fmt.Print("请输入扫描端口 (支持逗号分隔或范围，如 21-23,80,443,3389): ")
	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		fmt.Println("使用默认端口: 21-23,80,443,3389,3306,8080")
		input = "21-23,80,443,3389,3306,8080"
	}

	portStrs := strings.Split(input, ",")
	var ports []int

	for _, ps := range portStrs {
		ps = strings.TrimSpace(ps)

		if strings.Contains(ps, "-") {
			rangeParts := strings.Split(ps, "-")
			if len(rangeParts) == 2 {
				startPort, _ := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				endPort, _ := strconv.Atoi(strings.TrimSpace(rangeParts[1]))

				if startPort >= 1 && startPort <= 65535 && endPort >= 1 && endPort <= 65535 && startPort <= endPort {
					for port := startPort; port <= endPort; port++ {
						ports = append(ports, port)
					}
				}
			}
		} else {
			port, err := strconv.Atoi(ps)
			if err == nil && port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		fmt.Println("端口解析失败，使用默认端口")
		return []int{21, 22, 23, 80, 443, 3389, 3306, 8080}
	}

	return ports
}

// getDelayConfig 获取延迟配置
func (ui *InteractiveUI) getDelayConfig() (controller.DelayType, int) {
	fmt.Println("\n请选择延迟类型:")
	fmt.Println("1. 固定延迟 (constant)")
	fmt.Println("2. 随机延迟 (random)")
	fmt.Println("3. 线性增长 (function1)")
	fmt.Println("4. 正弦波动 (function2)")
	fmt.Println("5. 阶梯型 (function3)")
	fmt.Println("6. 随机步长 (function4)")
	fmt.Print("请输入选择 (1-6): ")

	choice, err := ui.readInputInt()
	if err != nil || choice < 1 || choice > 6 {
		fmt.Println("使用默认延迟: 固定延迟")
		return controller.ConstantDelay, 100
	}

	delayTypes := map[int]controller.DelayType{
		1: controller.ConstantDelay,
		2: controller.RandomDelay,
		3: controller.Function1,
		4: controller.Function2,
		5: controller.Function3,
		6: controller.Function4,
	}

	fmt.Print("请输入延迟基础值 (毫秒，默认100): ")
	delayVal, err := ui.readInputInt()
	if err != nil || delayVal <= 0 {
		delayVal = 100
	}

	return delayTypes[choice], delayVal
}

// getTimeout 获取超时时间
func (ui *InteractiveUI) getTimeout() int {
	fmt.Print("请输入连接超时时间 (秒，默认5): ")
	timeout, err := ui.readInputInt()
	if err != nil || timeout <= 0 {
		timeout = 5
	}
	return timeout
}

// getSMBUDPConfig 获取SMB/UDP扫描配置
func (ui *InteractiveUI) getSMBUDPConfig() (bool, bool) {
	fmt.Println("\n=== 高级扫描选项 ===")
	fmt.Println("SMB扫描: 检测Windows共享服务（端口445）")
	fmt.Println("UDP扫描: 检测UDP协议服务（DNS、NTP、SNMP等）")

	fmt.Print("是否启用SMB扫描？(y/n，默认n): ")
	input, _ := ui.reader.ReadString('\n')
	enableSMB := strings.TrimSpace(strings.ToLower(input)) == "y"

	fmt.Print("是否启用UDP扫描？(y/n，默认n): ")
	input, _ = ui.reader.ReadString('\n')
	enableUDP := strings.TrimSpace(strings.ToLower(input)) == "y"

	return enableSMB, enableUDP
}

// ShowScanProgress 显示扫描进度
func (ui *InteractiveUI) ShowScanProgress(step string, progress int, total int) {
	if total > 0 {
		percent := float64(progress) / float64(total) * 100

		// 确保进度不会超过100%
		if percent > 100 {
			percent = 100
		}

		// 生成进度条
		barLength := 50
		filledLength := int(percent / 100 * float64(barLength))
		bar := strings.Repeat("█", filledLength) + strings.Repeat("░", barLength-filledLength)

		fmt.Printf("\r%s: [%s] %d/%d (%.1f%%)", step, bar, progress, total, percent)
	} else {
		fmt.Printf("\r%s: 进行中...", step)
	}

	// 刷新输出缓冲区
	os.Stdout.Sync()
}

// ShowScanResult 显示扫描结果
func (ui *InteractiveUI) ShowScanResult(result *output.Result) {
	fmt.Println("\n\n=== 扫描结果 ===")
	fmt.Println()

	// 显示存活主机
	if len(result.AliveHosts) > 0 {
		fmt.Printf("存活主机 (%d 个):\n", len(result.AliveHosts))
		for i, host := range result.AliveHosts {
			fmt.Printf("  %d. %s", i+1, host)
			if osInfo, exists := result.OSInfo[host]; exists && osInfo != "" {
				fmt.Printf(" - %s", osInfo)
			}
			fmt.Println()
		}
		fmt.Println()
	} else {
		fmt.Println("未发现存活主机")
		return
	}

	// 显示开放端口和服务
	for host, ports := range result.OpenPorts {
		if len(ports) > 0 {
			fmt.Printf("主机 %s 的开放端口:\n", host)
			for _, port := range ports {
				fmt.Printf("  - 端口 %d", port)
				if services, exists := result.ServiceInfo[host]; exists {
					if service, exists := services[port]; exists && service != "" {
						fmt.Printf(" (%s)", service)
					}
				}
				fmt.Println()
			}
			fmt.Println()
		}
	}
}

// AskForContinue 询问是否继续
func (ui *InteractiveUI) AskForContinue() bool {
	fmt.Print("\n是否继续扫描？(y/n): ")
	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

// ShowHelp 显示帮助信息
func (ui *InteractiveUI) ShowHelp() {
	fmt.Println("\n=== 帮助信息 ===")
	fmt.Println("本工具提供以下功能:")
	fmt.Println("• 主机存活性探测 (ICMP/TCP)")
	fmt.Println("• TCP端口扫描")
	fmt.Println("• 服务识别和Banner抓取")
	fmt.Println("• 操作系统检测")
	fmt.Println("• 多种延迟控制算法")
	fmt.Println()
	fmt.Println("使用说明:")
	fmt.Println("1. 选择扫描模式")
	fmt.Println("2. 配置扫描参数")
	fmt.Println("3. 查看实时扫描进度")
	fmt.Println("4. 查看详细扫描结果")
	fmt.Println()
}

// readInputInt 读取整数输入
func (ui *InteractiveUI) readInputInt() (int, error) {
	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(input)
	return strconv.Atoi(input)
}

// ClearScreen 清屏
func (ui *InteractiveUI) ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// WaitForEnter 等待用户按回车
func (ui *InteractiveUI) WaitForEnter() {
	fmt.Print("\n按回车键继续...")
	ui.reader.ReadString('\n')
}

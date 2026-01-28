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
	delayType, delayValue := ui.getDelayConfig()

	// 获取超时时间
	timeout := ui.getTimeout()

	// 获取UDP扫描配置
	enableUDP := ui.getUDPConfig()

	return &controller.ScanParams{
		Targets:    targets,
		Ports:      ports,
		DelayType:  delayType,
		DelayValue: delayValue,
		Timeout:    timeout,
		EnableUDP:  enableUDP,
	}
}

// getUDPConfig 获取UDP扫描配置
func (ui *InteractiveUI) getUDPConfig() bool {
	fmt.Print("是否启用UDP扫描？(y/n，默认y): ")
	input, _ := ui.reader.ReadString('\n')
	enableUDP := strings.TrimSpace(strings.ToLower(input)) != "n"
	return enableUDP
}

// getTimeout 获取超时时间
func (ui *InteractiveUI) getTimeout() int {
	fmt.Print("请输入连接超时时间(秒，默认5秒): ")
	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return 5 // 默认超时时间
	}

	timeout, err := strconv.Atoi(input)
	if err != nil || timeout <= 0 {
		fmt.Println("无效的超时时间，使用默认值5秒")
		return 5
	}

	return timeout
}

// getTargets 获取目标主机列表
func (ui *InteractiveUI) getTargets() []string {
	fmt.Print("请输入目标主机（支持IP、域名、CIDR，多个目标用逗号分隔）: ")
	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return []string{"127.0.0.1"} // 默认目标
	}

	targets := strings.Split(input, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}
	return targets
}

// getPorts 获取端口列表
func (ui *InteractiveUI) getPorts() []int {
	fmt.Print("请输入端口范围（如: 80,443 或 1-1000，默认常用端口）: ")
	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		// 返回常用端口
		return []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
	}

	var ports []int
	// 处理端口范围
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 处理端口范围
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start <= end {
					for port := start; port <= end; port++ {
						ports = append(ports, port)
					}
				}
			}
		} else {
			// 处理单个端口
			port, err := strconv.Atoi(part)
			if err == nil {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		// 默认端口
		return []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
	}

	return ports
}

// getDelayConfig 获取延迟配置
func (ui *InteractiveUI) getDelayConfig() (controller.DelayType, int) {
	fmt.Println("\n延迟配置选项:")
	fmt.Println("1. 固定延迟 (constant)")
	fmt.Println("2. 随机延迟 (random)")
	fmt.Println("3. 线性增长 (function1)")
	fmt.Println("4. 正弦波动 (function2)")
	fmt.Println("5. 阶梯型 (function3)")
	fmt.Println("6. 随机步长 (function4)")
	fmt.Print("请选择延迟类型 (1-6，默认1): ")

	input, _ := ui.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var delayType controller.DelayType
	switch input {
	case "2":
		delayType = controller.RandomDelay
	case "3":
		delayType = controller.Function1
	case "4":
		delayType = controller.Function2
	case "5":
		delayType = controller.Function3
	case "6":
		delayType = controller.Function4
	default: // 包括 "1" 和无效输入
		delayType = controller.ConstantDelay
	}

	// 获取延迟基础值
	fmt.Print("请输入延迟基础值(毫秒，默认100): ")
	delayInput, _ := ui.reader.ReadString('\n')
	delayInput = strings.TrimSpace(delayInput)

	if delayInput == "" {
		return delayType, 100 // 默认延迟值
	}

	delayValue, err := strconv.Atoi(delayInput)
	if err != nil || delayValue <= 0 {
		fmt.Println("无效的延迟值，使用默认值100毫秒")
		return delayType, 100
	}

	return delayType, delayValue
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

// ShowScanResult 显示扫描结果（统一格式）
func (ui *InteractiveUI) ShowScanResult(result *output.Result) {
	// 使用与命令行模式相同的统一格式
	result.Print()
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

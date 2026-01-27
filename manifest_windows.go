//go:build windows
// +build windows

package main

import (
	_ "embed"
	"os"
	"syscall"
	"unsafe"
)

//go:embed project.exe.manifest
var manifestData []byte

// 检查当前是否具有管理员权限
func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// 请求UAC提权（如果尚未具有管理员权限）
func requestUACElevation() bool {
	if isAdmin() {
		return true
	}

	// 获取当前可执行文件路径
	exePath, err := os.Executable()
	if err != nil {
		return false
	}

	// 使用ShellExecute以管理员身份重新启动
	verb := syscall.StringToUTF16Ptr("runas")
	file := syscall.StringToUTF16Ptr(exePath)

	// 构建参数
	var params string
	if len(os.Args) > 1 {
		for i := 1; i < len(os.Args); i++ {
			params += " " + os.Args[i]
		}
	}

	paramPtr := syscall.StringToUTF16Ptr(params)

	// 调用ShellExecute
	ret, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(paramPtr)),
		0,
		uintptr(1), // SW_SHOWNORMAL
	)

	return int(ret) > 32
}

// 导出提权函数供其他包使用
func IsAdmin() bool {
	return isAdmin()
}

func RequestUACElevation() bool {
	return requestUACElevation()
}

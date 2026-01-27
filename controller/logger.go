package controller

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger 日志记录器
type Logger struct {
	file   *os.File   // 日志文件句柄
	mu     sync.Mutex // 互斥锁，保证多协程安全写入
	closed bool       // 日志是否已关闭
}

// NewLogger 初始化日志记录器，创建/追加日志文件
func NewLogger(filename string) *Logger {
	// 打开日志文件：不存在则创建，存在则追加写入
	file, err := os.OpenFile(
		filename,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0600, // 更安全的文件权限：仅所有者读写
	)
	if err != nil {
		fmt.Printf("日志文件创建失败: %v，将使用标准输出记录日志\n", err)
		return &Logger{file: os.Stdout} //  fallback 到标准输出
	}

	return &Logger{
		file:   file,
		mu:     sync.Mutex{},
		closed: false,
	}
}

// 格式化日志前缀（包含时间和日志级别）
func (l *Logger) formatPrefix(level string) string {
	return fmt.Sprintf("[%s] [%s] ", time.Now().Format("2006-01-02 15:04:05.000"), level)
}

// Log 记录普通信息日志
func (l *Logger) Log(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		fmt.Println("日志器已关闭，无法记录日志:", msg)
		return
	}

	if l.file == nil {
		fmt.Println("日志文件未初始化:", msg)
		return
	}

	// 写入格式化日志
	_, err := l.file.WriteString(l.formatPrefix("INFO") + msg + "\n")
	if err != nil {
		fmt.Printf("日志写入失败: %v\n", err)
	}
}

// Logf 记录格式化普通信息日志（支持占位符）
func (l *Logger) Logf(format string, v ...interface{}) {
	l.Log(fmt.Sprintf(format, v...))
}

// Error 记录错误日志
func (l *Logger) Error(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		fmt.Println("日志器已关闭，无法记录错误日志:", msg)
		return
	}

	if l.file == nil {
		fmt.Println("日志文件未初始化:", msg)
		return
	}

	_, err := l.file.WriteString(l.formatPrefix("ERROR") + msg + "\n")
	if err != nil {
		fmt.Printf("错误日志写入失败: %v\n", err)
	}
}

// Errorf 记录格式化错误日志（支持占位符）
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.Error(fmt.Sprintf(format, v...))
}

// Close 关闭日志文件句柄，释放资源
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed || l.file == os.Stdout || l.file == nil {
		return
	}

	err := l.file.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "日志文件关闭失败: %v\n", err)
	} else {
		l.closed = true
		fmt.Printf("日志文件已成功关闭，日志保存路径: %s\n", l.file.Name())
	}
}

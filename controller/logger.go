package controller

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Async Logger: single writer goroutine + buffered channel
// - Non-blocking producers (Log/Logf/Error/Errorf) push formatted lines into a buffered channel.
// - A single background goroutine reads the channel and writes to a bufio.Writer.
// - If the channel is full, producers fall back to a synchronous write path to avoid message loss.
// - Close() flushes remaining entries and closes file. Close is idempotent via sync.Once.
type Logger struct {
	file     *os.File
	writer   *bufio.Writer
	entryCh  chan string
	wg       sync.WaitGroup
	once     sync.Once
	closed   uint32 // atomic: 0 = open, 1 = closed
	writerMu sync.Mutex
}

// NewLogger 初始化异步日志记录器（向后兼容原调用 NewLogger(filename)）
func NewLogger(filename string) *Logger {
	// 打开日志文件：不存在则创建，存在则追加写入
	file, err := os.OpenFile(
		filename,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, // 修改为覆盖模式
		0600,
	)
	if err != nil {
		fmt.Printf("日志文件创建失败: %v，将使用标准输出记录日志\n", err)
		// 使用 stdout，使用一个小缓冲通道也有意义
		l := &Logger{
			file:    os.Stdout,
			writer:  bufio.NewWriter(os.Stdout),
			entryCh: make(chan string, 1024),
		}
		l.wg.Add(1)
		go l.runWriter()
		return l
	}

	l := &Logger{
		file:    file,
		writer:  bufio.NewWriter(file),
		entryCh: make(chan string, 4096), // 可调缓冲大小
	}
	l.wg.Add(1)
	go l.runWriter()
	return l
}

// runWriter: 单写入协程，负责从 channel 拉取日志并写入缓冲 writer
func (l *Logger) runWriter() {
	defer l.wg.Done()
	for msg := range l.entryCh {
		l.writerMu.Lock()
		_, _ = l.writer.WriteString(msg)
		l.writerMu.Unlock()
	}
	// channel 关闭后，flush 剩余缓冲
	l.writerMu.Lock()
	_ = l.writer.Flush()
	l.writerMu.Unlock()
}

// helper: 尝试把消息推到 channel；如果 channel 已关闭或已满，退回到同步写入
func (l *Logger) enqueue(msg string) {
	if atomic.LoadUint32(&l.closed) == 1 {
		// 已关闭：把日志打印到标准输出以避免丢失
		fmt.Println("日志器已关闭，无法记录日志:", msg)
		return
	}

	// 尝试非阻塞发送到通道
	select {
	case l.entryCh <- msg:
		// 已成功排入队列
	default:
		// 通道已满：降级为同步写入，避免丢失（仍使用 writerMu 以避免并发写冲突）
		l.writerMu.Lock()
		_, err := l.writer.WriteString(msg)
		if err == nil {
			// 为尽量保证能看到实时日志，立即 flush（可根据性能调整）
			_ = l.writer.Flush()
		}
		l.writerMu.Unlock()
	}
}

// 格式化日志前缀（包含时间和日志级别）
func (l *Logger) formatPrefix(level string) string {
	return fmt.Sprintf("[%s] [%s] ", time.Now().Format("2006-01-02 15:04:05.000"), level)
}

// Log 记录普通信息日志
func (l *Logger) Log(msg string) {
	line := l.formatPrefix("INFO") + msg + "\n"
	l.enqueue(line)
}

// Logf 记录格式化普通信息日志（支持占位符）
func (l *Logger) Logf(format string, v ...interface{}) {
	l.Log(fmt.Sprintf(format, v...))
}

// Error 记录错误日志
func (l *Logger) Error(msg string) {
	line := l.formatPrefix("ERROR") + msg + "\n"
	l.enqueue(line)
}

// Errorf 记录格式化错误日志（支持占位符）
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.Error(fmt.Sprintf(format, v...))
}

// Fatalf 记录格式化致命错误日志并退出程序
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.Errorf(format, v...)
	os.Exit(1)
}

// Close 关闭日志记录器：关闭 channel，等待写入完成并关闭文件。
// Close 是幂等的（使用 sync.Once via l.once）
func (l *Logger) Close() {
	l.once.Do(func() {
		// 标记已关闭，防止新的入队
		atomic.StoreUint32(&l.closed, 1)

		// 先关闭通道，触发后台写入协程退出（确保生产者不会再向 channel 发送数据）
		close(l.entryCh)

		// 等待后台写入完成
		l.wg.Wait()

		// 确保缓冲区已 flush（runWriter 在退出前已经 flush 了，但做一次保险）
		l.writerMu.Lock()
		_ = l.writer.Flush()
		l.writerMu.Unlock()

		// 关闭文件（若为 stdout，不关闭）
		if l.file != nil && l.file != os.Stdout {
			if err := l.file.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "日志文件关闭失败: %v\n", err)
			} else {
				fmt.Printf("日志文件已成功关闭，日志保存路径: %s\n", l.file.Name())
			}
		}
	})
}

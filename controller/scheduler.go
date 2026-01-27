package controller

import (
	"time"
)

type Scheduler struct {
	delayType DelayType
	delayVal  int
	logger    *Logger
	step      int
}

func NewScheduler(dt DelayType, dv int, logger *Logger) *Scheduler {
	return &Scheduler{
		delayType: dt,
		delayVal:  dv,
		logger:    logger,
		step:      50, // 步长默认值
	}
}

// Schedule 调度扫描任务并添加延迟
func (s *Scheduler) Schedule(task func() interface{}) interface{} {
	delay := GetDelay(s.delayType, s.delayVal, s.step)
	// 改进：更详细的延迟日志
	s.logger.Logf("任务调度: 延迟类型=%s, 基础值=%dms, 步长=%d, 实际延迟=%v",
		s.delayType, s.delayVal, s.step, delay)
	time.Sleep(delay)
	result := task()
	s.logger.Logf("任务完成，结果类型: %T", result)
	s.step++ // 增加步长
	return result
}

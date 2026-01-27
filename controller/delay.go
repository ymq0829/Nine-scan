package controller

import (
	"math/rand"
	"time"
)

// DelayType 延迟类型：constant/random/function1-function4
type DelayType string

const (
	ConstantDelay DelayType = "constant"
	RandomDelay   DelayType = "random"
	Function1     DelayType = "function1" // 线性增长
	Function2     DelayType = "function2" // 正弦波动
	Function3     DelayType = "function3" // 阶梯型
	Function4     DelayType = "function4" // 随机步长
)

// 初始化随机种子（只执行一次）
var randomInitialized = false

func init() {
	if !randomInitialized {
		rand.Seed(time.Now().UnixNano())
		randomInitialized = true
	}
}

// GetDelay 根据类型生成延迟时间
func GetDelay(t DelayType, base int, step int) time.Duration {
	switch t {
	case ConstantDelay:
		return time.Duration(base) * time.Millisecond
	case RandomDelay:
		// 修复：生成真正的随机延迟，范围在base/2到base*1.5之间
		min := base / 2
		if min < 10 {
			min = 10 // 最小延迟10ms
		}
		max := base * 3 / 2
		if max < min+10 {
			max = min + 10
		}
		return time.Duration(min+rand.Intn(max-min)) * time.Millisecond
	case Function1:
		return time.Duration(base+step*rand.Intn(5)) * time.Millisecond
	case Function2:
		return time.Duration(base+int(float64(step)*rand.Float64())) * time.Millisecond
	case Function3:
		return time.Duration(base+step*(rand.Intn(3)+1)) * time.Millisecond
	case Function4:
		return time.Duration(base+rand.Intn(step)*2) * time.Millisecond
	default:
		return 100 * time.Millisecond
	}
}

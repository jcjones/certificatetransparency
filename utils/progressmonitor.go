package utils

import (
	"fmt"
	"time"
)

type ProgressMonitor struct {
	lastTime       time.Time
	lastCount      int64
	length         int64
	ticksPerMinute float64
	cachedString   string
}

func NewProgressMonitor() *ProgressMonitor {
	return &ProgressMonitor{
		lastTime:       time.Time{},
		lastCount:      int64(0),
		length:         int64(0),
		ticksPerMinute: float64(0.0),
		cachedString:   "?",
	}
}

func (pm *ProgressMonitor) getTimeRemaining() time.Duration {
	minutesRemaining := float64(pm.length-pm.lastCount) / pm.ticksPerMinute
	return time.Duration(minutesRemaining) * time.Minute
}

func (pm *ProgressMonitor) String() string {
	return pm.cachedString
}

func (pm *ProgressMonitor) UpdateCount(newCount int64) error {
	nowTime := time.Now()
	countChange := newCount - pm.lastCount

	if !pm.lastTime.IsZero() {
		timeElapsed := nowTime.Sub(pm.lastTime)
		pm.ticksPerMinute = float64(countChange) / timeElapsed.Minutes()
		pm.cachedString = fmt.Sprintf("%.0f/minute (%s remaining)", pm.getInstantRateMinute(), pm.getTimeRemaining())
	}

	pm.lastCount = newCount
	pm.lastTime = nowTime

	return nil
}

func (pm *ProgressMonitor) UpdateLength(newLength int64) error {
	pm.length = newLength
	return nil
}

func (pm *ProgressMonitor) getInstantRateMinute() float64 {
	return pm.ticksPerMinute
}

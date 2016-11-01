package utils

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type OperationStatus struct {
	// Identifier of this Status Update
	Identifier string
	// Start contains the requested starting index of the operation.
	Start uint64
	// Current contains the greatest index that has been processed.
	Current uint64
	// Length contains the total number of entries.
	Length uint64
}

func (status OperationStatus) Percentage() float32 {
	total := float32(status.Length - status.Start)
	done := float32(status.Current - status.Start)

	if total == 0 {
		return 100
	}
	return done * 100 / total
}

type ProgressMonitor struct {
	lastTime       time.Time
	lastCount      uint64
	length         uint64
	ticksPerMinute float64
	cachedString   string
}

func NewProgressMonitor() *ProgressMonitor {
	return &ProgressMonitor{
		lastTime:       time.Time{},
		lastCount:      uint64(0),
		length:         uint64(0),
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

func (pm *ProgressMonitor) UpdateCount(identifier string, newCount uint64) error {
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

func (pm *ProgressMonitor) UpdateLength(identifier string, newLength uint64) error {
	pm.length = newLength
	return nil
}

func (pm *ProgressMonitor) getInstantRateMinute() float64 {
	return pm.ticksPerMinute
}

func clearLine() {
	fmt.Printf("\x1b[80D\x1b[2K")
}

type ProgressDisplay struct {
	statusChan chan OperationStatus
}

func NewProgressDisplay() *ProgressDisplay {
	return &ProgressDisplay{
		statusChan: make(chan OperationStatus, 1),
	}
}

func (pd *ProgressDisplay) UpdateProgress(identifier string, start uint64, index uint64, upTo uint64) {
	pd.statusChan <- OperationStatus{identifier, start, index, upTo}
}

func (pd *ProgressDisplay) Close() {
	close(pd.statusChan)
}

func (pd *ProgressDisplay) StartDisplay(wg *sync.WaitGroup) {
	wg.Add(1)

	go func() {
		defer wg.Done()
		symbols := []string{"|", "/", "-", "\\"}
		symbolIndex := 0

		status, ok := <-pd.statusChan
		if !ok {
			return
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		isInteractive := strings.Contains(os.Getenv("TERM"), "xterm") || strings.Contains(os.Getenv("TERM"), "screen")

		if !isInteractive {
			ticker.Stop()
		}

		// Speed statistics
		progressMonitor := NewProgressMonitor()

		for {
			select {
			case status, ok = <-pd.statusChan:
				if !ok {
					if isInteractive {
						clearLine()
					}
					return
				}

				// Track speed statistics
				progressMonitor.UpdateCount(status.Identifier, status.Current)
				progressMonitor.UpdateLength(status.Identifier, status.Length)
			case <-ticker.C:
				symbolIndex = (symbolIndex + 1) % len(symbols)
			}

			// Display the line
			statusLine := fmt.Sprintf("%.1f%% (%d of %d) Rate: %s", status.Percentage(), status.Current, status.Length, progressMonitor)

			if isInteractive {
				clearLine()
				fmt.Printf("%s %s", symbols[symbolIndex], statusLine)
			} else {
				fmt.Println(statusLine)
			}
		}
	}()
}

package assurance

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Continuous Assurance Monitoring
// ---------------------------------------------------------------------------
//
// ContinuousMonitor provides real-time compliance posture monitoring by
// periodically evaluating the platform's assurance state across configured
// compliance frameworks.
//
// Features:
//   - Periodic compliance posture evaluation
//   - Trend tracking over configurable periods
//   - Alert thresholds for degradation detection
//   - Notification callbacks for compliance events
// ---------------------------------------------------------------------------

// MonitorConfig configures continuous monitoring behavior.
type MonitorConfig struct {
	// Interval between compliance checks.
	Interval time.Duration `json:"interval"`

	// Frameworks lists the compliance frameworks to monitor.
	Frameworks []string `json:"frameworks"`

	// AlertThreshold is the minimum overall score (0-100) before an alert
	// is triggered. Scores below this trigger the NotifyOnDegradation callback.
	AlertThreshold float64 `json:"alert_threshold"`

	// NotifyOnDegradation is called when the compliance posture drops below
	// the alert threshold. May be nil to suppress notifications.
	NotifyOnDegradation func(posture *CompliancePosture)

	// JobIDs lists specific job IDs to monitor. If empty, monitoring
	// operates in aggregate mode across all recent jobs.
	JobIDs []string `json:"job_ids,omitempty"`
}

// Validate checks the configuration for correctness.
func (mc *MonitorConfig) Validate() error {
	if mc.Interval <= 0 {
		return fmt.Errorf("assurance/monitor: interval must be positive")
	}
	if mc.AlertThreshold < 0 || mc.AlertThreshold > 100 {
		return fmt.Errorf("assurance/monitor: alert threshold must be between 0 and 100")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Compliance posture
// ---------------------------------------------------------------------------

// CompliancePosture represents the current compliance state.
type CompliancePosture struct {
	// OverallScore is the aggregate compliance score (0-100).
	OverallScore float64 `json:"overall_score"`

	// FrameworkScores maps framework identifiers to individual scores.
	FrameworkScores map[string]float64 `json:"framework_scores"`

	// Gaps lists identified compliance gaps.
	Gaps []ComplianceGap `json:"gaps,omitempty"`

	// LastChecked records the most recent evaluation time.
	LastChecked time.Time `json:"last_checked"`

	// Trend indicates the direction of compliance score change.
	Trend TrendDirection `json:"trend"`

	// AssuranceDistribution counts jobs at each assurance level.
	AssuranceDistribution map[string]int `json:"assurance_distribution"`
}

// ComplianceGap describes a specific compliance deficiency.
type ComplianceGap struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"control_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // "critical", "high", "medium", "low"
	DetectedAt  string `json:"detected_at"`
}

// TrendDirection indicates compliance posture trend.
type TrendDirection string

const (
	TrendImproving  TrendDirection = "improving"
	TrendStable     TrendDirection = "stable"
	TrendDegrading  TrendDirection = "degrading"
	TrendUnknown    TrendDirection = "unknown"
)

// ---------------------------------------------------------------------------
// Trend history
// ---------------------------------------------------------------------------

// PostureSnapshot records a posture at a point in time for trend analysis.
type PostureSnapshot struct {
	Score     float64   `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}

// TrendReport describes compliance trends over a period.
type TrendReport struct {
	Period     time.Duration      `json:"period"`
	Snapshots  []PostureSnapshot  `json:"snapshots"`
	Direction  TrendDirection     `json:"direction"`
	ChangeRate float64            `json:"change_rate"` // points per hour
}

// ---------------------------------------------------------------------------
// Continuous Monitor
// ---------------------------------------------------------------------------

// ContinuousMonitor evaluates compliance posture on a schedule.
type ContinuousMonitor struct {
	fabric   *AssuranceFabric
	config   MonitorConfig
	mu       sync.RWMutex
	current  *CompliancePosture
	history  []PostureSnapshot
	running  bool
	cancelFn context.CancelFunc
}

// NewContinuousMonitor creates a new monitor backed by the given fabric.
func NewContinuousMonitor(fabric *AssuranceFabric) *ContinuousMonitor {
	return &ContinuousMonitor{
		fabric:  fabric,
		history: make([]PostureSnapshot, 0, 1000),
	}
}

// StartMonitoring begins continuous compliance monitoring. It is safe to
// call multiple times; subsequent calls return an error if already running.
func (cm *ContinuousMonitor) StartMonitoring(ctx context.Context, config MonitorConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	cm.mu.Lock()
	if cm.running {
		cm.mu.Unlock()
		return fmt.Errorf("assurance/monitor: already running")
	}
	cm.config = config
	cm.running = true

	monitorCtx, cancel := context.WithCancel(ctx)
	cm.cancelFn = cancel
	cm.mu.Unlock()

	// Perform initial check.
	cm.evaluate(monitorCtx)

	// Start the monitoring loop.
	go cm.loop(monitorCtx)

	return nil
}

// StopMonitoring halts the continuous monitoring loop.
func (cm *ContinuousMonitor) StopMonitoring() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.cancelFn != nil {
		cm.cancelFn()
	}
	cm.running = false
}

// IsRunning returns whether the monitor is actively running.
func (cm *ContinuousMonitor) IsRunning() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.running
}

// GetPosture returns the most recent compliance posture.
func (cm *ContinuousMonitor) GetPosture(_ context.Context) (*CompliancePosture, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.current == nil {
		return nil, fmt.Errorf("assurance/monitor: no posture available (monitoring not started or no data yet)")
	}
	posture := *cm.current
	return &posture, nil
}

// GetTrend returns a trend report over the specified period.
func (cm *ContinuousMonitor) GetTrend(_ context.Context, period time.Duration) (*TrendReport, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if len(cm.history) == 0 {
		return nil, fmt.Errorf("assurance/monitor: no history available")
	}

	cutoff := time.Now().UTC().Add(-period)
	var relevant []PostureSnapshot
	for _, s := range cm.history {
		if s.Timestamp.After(cutoff) {
			relevant = append(relevant, s)
		}
	}

	if len(relevant) == 0 {
		return nil, fmt.Errorf("assurance/monitor: no data within requested period")
	}

	report := &TrendReport{
		Period:    period,
		Snapshots: relevant,
	}

	// Compute trend direction and rate.
	if len(relevant) < 2 {
		report.Direction = TrendUnknown
		report.ChangeRate = 0
	} else {
		first := relevant[0]
		last := relevant[len(relevant)-1]
		delta := last.Score - first.Score
		hours := last.Timestamp.Sub(first.Timestamp).Hours()
		if hours > 0 {
			report.ChangeRate = delta / hours
		}

		if delta > 1 {
			report.Direction = TrendImproving
		} else if delta < -1 {
			report.Direction = TrendDegrading
		} else {
			report.Direction = TrendStable
		}
	}

	return report, nil
}

// ---------------------------------------------------------------------------
// Internal monitoring loop
// ---------------------------------------------------------------------------

func (cm *ContinuousMonitor) loop(ctx context.Context) {
	ticker := time.NewTicker(cm.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cm.mu.Lock()
			cm.running = false
			cm.mu.Unlock()
			return
		case <-ticker.C:
			cm.evaluate(ctx)
		}
	}
}

func (cm *ContinuousMonitor) evaluate(ctx context.Context) {
	posture := &CompliancePosture{
		LastChecked:           time.Now().UTC(),
		FrameworkScores:       make(map[string]float64),
		AssuranceDistribution: make(map[string]int),
	}

	cm.mu.RLock()
	jobIDs := cm.config.JobIDs
	cm.mu.RUnlock()

	if len(jobIDs) == 0 {
		// No specific jobs configured; produce a baseline posture.
		posture.OverallScore = 0
		posture.Trend = TrendUnknown
	} else {
		var totalScore float64
		for _, jid := range jobIDs {
			evidence, err := cm.fabric.CollectEvidence(ctx, jid)
			if err != nil {
				continue
			}
			score := float64(evidence.AssuranceLevel.Score())
			totalScore += score
			levelName := evidence.AssuranceLevel.String()
			posture.AssuranceDistribution[levelName]++

			// Aggregate compliance scores.
			if evidence.Compliance != nil {
				posture.FrameworkScores["aggregate"] = evidence.Compliance.CoverageScore
			}
		}
		if len(jobIDs) > 0 {
			posture.OverallScore = totalScore / float64(len(jobIDs))
		}
	}

	// Compute trend from history.
	cm.mu.RLock()
	histLen := len(cm.history)
	cm.mu.RUnlock()

	if histLen > 0 {
		cm.mu.RLock()
		prev := cm.history[histLen-1]
		cm.mu.RUnlock()
		delta := posture.OverallScore - prev.Score
		if delta > 1 {
			posture.Trend = TrendImproving
		} else if delta < -1 {
			posture.Trend = TrendDegrading
		} else {
			posture.Trend = TrendStable
		}
	} else {
		posture.Trend = TrendUnknown
	}

	// Store the posture.
	cm.mu.Lock()
	cm.current = posture
	cm.history = append(cm.history, PostureSnapshot{
		Score:     posture.OverallScore,
		Timestamp: posture.LastChecked,
	})

	// Keep history bounded.
	if len(cm.history) > 10000 {
		cm.history = cm.history[len(cm.history)-5000:]
	}

	threshold := cm.config.AlertThreshold
	notify := cm.config.NotifyOnDegradation
	cm.mu.Unlock()

	// Fire alert if below threshold.
	if posture.OverallScore < threshold && notify != nil {
		notify(posture)
	}
}

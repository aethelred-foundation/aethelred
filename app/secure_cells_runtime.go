package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cast"

	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

const (
	secureCellAutomatedSweepActor        = "system:secure-cells-expiry-sweeper"
	defaultSecureCellExpirySweepInterval = time.Minute
	defaultSecureCellWebhookTimeout      = 5 * time.Second
	defaultSecureCellWebhookRetryBackoff = 500 * time.Millisecond
	defaultSecureCellWebhookMaxAttempts  = 3
	defaultSecureCellWebhookQueueSize    = 128
	defaultSecureCellWebhookWorkers      = 2
)

type secureCellWebhookDeliveryStatus string

const (
	secureCellWebhookDeliveryPending   secureCellWebhookDeliveryStatus = "pending"
	secureCellWebhookDeliverySucceeded secureCellWebhookDeliveryStatus = "succeeded"
	secureCellWebhookDeliveryFailed    secureCellWebhookDeliveryStatus = "failed"
)

type secureCellWebhookConfig struct {
	Endpoints    []string
	BearerToken  string
	HMACSecret   string
	Timeout      time.Duration
	RetryBackoff time.Duration
	MaxAttempts  int
	QueueSize    int
	Workers      int
}

type secureCellWebhookDeliveryRecord struct {
	DeliveryID    string                          `json:"delivery_id"`
	EventID       string                          `json:"event_id"`
	CellID        string                          `json:"cell_id"`
	Action        string                          `json:"action"`
	Endpoint      string                          `json:"endpoint"`
	Status        secureCellWebhookDeliveryStatus `json:"status"`
	Attempts      int                             `json:"attempts"`
	LastError     string                          `json:"last_error,omitempty"`
	LastAttemptAt *time.Time                      `json:"last_attempt_at,omitempty"`
	DeliveredAt   *time.Time                      `json:"delivered_at,omitempty"`
	CreatedAt     time.Time                       `json:"created_at"`
	UpdatedAt     time.Time                       `json:"updated_at"`
}

type secureCellWebhookDeliveryFilter struct {
	CellID   string
	EventID  string
	Endpoint string
	Status   secureCellWebhookDeliveryStatus
	Limit    int
}

type secureCellAuditEventFilter struct {
	CellID         string
	ParticipantDID string
	ThreadID       string
	DecisionID     string
	Action         string
	Actor          string
	SinceSequence  uint64
	Limit          int
}

type secureCellAuditEventRecord struct {
	Sequence          uint64                   `json:"sequence"`
	RecordHash        string                   `json:"record_hash"`
	BlockHeight       int64                    `json:"block_height"`
	Timestamp         string                   `json:"timestamp"`
	Category          pouwkeeper.AuditCategory `json:"category"`
	Severity          pouwkeeper.AuditSeverity `json:"severity"`
	Action            string                   `json:"action"`
	Actor             string                   `json:"actor"`
	CellID            string                   `json:"cell_id,omitempty"`
	EventID           string                   `json:"event_id,omitempty"`
	ParticipantDID    string                   `json:"participant_did,omitempty"`
	ThreadID          string                   `json:"thread_id,omitempty"`
	DecisionID        string                   `json:"decision_id,omitempty"`
	CellStatus        string                   `json:"cell_status,omitempty"`
	ControlLedgerID   string                   `json:"control_ledger_id,omitempty"`
	PortablePackageID string                   `json:"portable_package_hash,omitempty"`
	Details           map[string]string        `json:"details,omitempty"`
}

type secureCellWebhookDeliveryTask struct {
	deliveryID string
	endpoint   string
	event      securecellsintegration.SecureCellLifecycleEvent
}

type secureCellLifecycleRuntime struct {
	app    *AethelredApp
	config secureCellWebhookConfig
	client *http.Client

	mu         sync.RWMutex
	deliveries []secureCellWebhookDeliveryRecord

	queue    chan secureCellWebhookDeliveryTask
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

type secureCellExpirySweeper struct {
	app      *AethelredApp
	service  *securecellsintegration.Service
	interval time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

type secureCellStopAdapter struct {
	name    string
	stopper interface {
		Stop()
	}
}

func (a *secureCellStopAdapter) Name() string { return a.name }

func (a *secureCellStopAdapter) Shutdown(ctx context.Context) error {
	if a == nil || a.stopper == nil {
		return nil
	}
	a.stopper.Stop()
	return nil
}

func newSecureCellLifecycleRuntime(app *AethelredApp, config secureCellWebhookConfig) *secureCellLifecycleRuntime {
	if app == nil {
		return nil
	}
	config = normalizeSecureCellWebhookConfig(config)
	runtime := &secureCellLifecycleRuntime{
		app:    app,
		config: config,
		client: &http.Client{Timeout: config.Timeout},
		stopCh: make(chan struct{}),
	}
	if len(runtime.config.Endpoints) == 0 || runtime.config.Workers <= 0 {
		return runtime
	}
	runtime.queue = make(chan secureCellWebhookDeliveryTask, runtime.config.QueueSize)
	for worker := 0; worker < runtime.config.Workers; worker++ {
		runtime.wg.Add(1)
		go runtime.deliveryLoop()
	}
	return runtime
}

func (r *secureCellLifecycleRuntime) Publish(ctx context.Context, event securecellsintegration.SecureCellLifecycleEvent) {
	if r == nil {
		return
	}
	r.recordAuditEvent(event)
	r.enqueueWebhookDeliveries(ctx, event)
}

func (r *secureCellLifecycleRuntime) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
		r.wg.Wait()
	})
}

func (r *secureCellLifecycleRuntime) ListDeliveries(filter secureCellWebhookDeliveryFilter) []secureCellWebhookDeliveryRecord {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]secureCellWebhookDeliveryRecord, 0, len(r.deliveries))
	for _, delivery := range r.deliveries {
		if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(delivery.CellID), strings.TrimSpace(filter.CellID)) {
			continue
		}
		if filter.EventID != "" && !strings.EqualFold(strings.TrimSpace(delivery.EventID), strings.TrimSpace(filter.EventID)) {
			continue
		}
		if filter.Endpoint != "" && !strings.EqualFold(strings.TrimSpace(delivery.Endpoint), strings.TrimSpace(filter.Endpoint)) {
			continue
		}
		if filter.Status != "" && delivery.Status != filter.Status {
			continue
		}
		items = append(items, cloneSecureCellWebhookDelivery(delivery))
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items
}

func newSecureCellExpirySweeper(app *AethelredApp, service *securecellsintegration.Service, interval time.Duration) *secureCellExpirySweeper {
	interval = normalizeSecureCellExpirySweepInterval(interval)
	if app == nil || service == nil || interval <= 0 {
		return nil
	}
	sweeper := &secureCellExpirySweeper{
		app:      app,
		service:  service,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
	sweeper.wg.Add(1)
	go sweeper.loop()
	return sweeper
}

func (s *secureCellExpirySweeper) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.wg.Wait()
	})
}

func (s *secureCellExpirySweeper) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.runSweep()
		case <-s.stopCh:
			return
		}
	}
}

func (s *secureCellExpirySweeper) runSweep() {
	if s == nil || s.service == nil {
		return
	}
	now := time.Now().UTC()
	lifecycle := securecellsintegration.SecureCellLifecycleRequest{
		ActorDID: secureCellAutomatedSweepActor,
		Reason:   "automated quarantine expiry sweep",
		Metadata: map[string]string{
			"sweep_mode": "automated",
		},
	}
	report, err := s.service.SweepExpiredQuarantines(context.Background(), now, lifecycle)
	if err != nil {
		if s.app != nil {
			s.app.Logger().Error("Secure Cells automated quarantine-expiry sweep failed", "error", err)
		}
	} else if report != nil && report.ParticipantsReleased > 0 {
		if s.app != nil {
			s.app.Logger().Info("Secure Cells automated quarantine-expiry sweep completed",
				"cells_mutated", report.CellsMutated,
				"participants_released", report.ParticipantsReleased,
			)
		}
	}
	s.runDecisionGovernanceSweep(now)
	s.runFederationGovernanceSweep(now)
}

func (s *secureCellExpirySweeper) runDecisionGovernanceSweep(at time.Time) {
	if s == nil {
		return
	}
	result, ok, err := invokeSecureCellDecisionGovernanceSweep(s.service, at, securecellsintegration.SecureCellLifecycleRequest{
		ActorDID: secureCellAutomatedSweepActor,
		Reason:   "automated decision governance sweep",
		Metadata: map[string]string{
			"sweep_mode":      "automated",
			"workflow":        "secure_cell",
			"automation_mode": "decision_governance",
		},
	})
	if err != nil {
		if s.app != nil {
			s.app.Logger().Error("Secure Cells automated decision-governance sweep failed", "error", err)
		}
		return
	}
	if !ok {
		return
	}
	if s.app != nil {
		s.app.Logger().Info("Secure Cells automated decision-governance sweep completed", "result", result)
	}
}

func (s *secureCellExpirySweeper) runFederationGovernanceSweep(at time.Time) {
	if s == nil {
		return
	}
	result, ok, err := invokeSecureCellFederationGovernanceSweep(s.service, at, securecellsintegration.SecureCellLifecycleRequest{
		ActorDID: secureCellAutomatedSweepActor,
		Reason:   "automated federation governance sweep",
		Metadata: map[string]string{
			"sweep_mode":           "automated",
			"workflow":             "secure_cell",
			"automation_mode":      "federation_governance",
			"federation_sweep_mode": "automated",
		},
	})
	if err != nil {
		if s.app != nil {
			s.app.Logger().Error("Secure Cells automated federation-governance sweep failed", "error", err)
		}
		return
	}
	if !ok {
		return
	}
	if s.app != nil {
		s.app.Logger().Info("Secure Cells automated federation-governance sweep completed", "result", result)
	}
}

func invokeSecureCellDecisionGovernanceSweep(service any, at time.Time, lifecycle securecellsintegration.SecureCellLifecycleRequest) (any, bool, error) {
	if service == nil {
		return nil, false, nil
	}
	value := reflect.ValueOf(service)
	if !value.IsValid() {
		return nil, false, nil
	}
	var method reflect.Value
	for _, name := range []string{"SweepDecisionGovernance", "SweepAutomatedDecisionGovernance", "SweepDecisionAutomation"} {
		method = value.MethodByName(name)
		if method.IsValid() {
			break
		}
	}
	if !method.IsValid() {
		return nil, false, nil
	}
	in := []reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.ValueOf(at.UTC()),
		reflect.ValueOf(lifecycle),
	}
	out := method.Call(in)
	switch len(out) {
	case 0:
		return nil, true, nil
	case 1:
		if err, ok := out[0].Interface().(error); ok && err != nil {
			return nil, true, err
		}
		return out[0].Interface(), true, nil
	default:
		var result any
		if out[0].IsValid() {
			result = out[0].Interface()
		}
		if len(out) > 1 {
			if err, ok := out[1].Interface().(error); ok && err != nil {
				return result, true, err
			}
		}
		return result, true, nil
	}
}

func invokeSecureCellFederationGovernanceSweep(service any, at time.Time, lifecycle securecellsintegration.SecureCellLifecycleRequest) (any, bool, error) {
	if service == nil {
		return nil, false, nil
	}
	value := reflect.ValueOf(service)
	if !value.IsValid() {
		return nil, false, nil
	}
	var method reflect.Value
	for _, name := range []string{"SweepFederationGovernance", "SweepAutomatedFederationGovernance", "SweepFederationAutomation"} {
		method = value.MethodByName(name)
		if method.IsValid() {
			break
		}
	}
	if !method.IsValid() {
		return nil, false, nil
	}
	in := []reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.ValueOf(at.UTC()),
		reflect.ValueOf(lifecycle),
	}
	out := method.Call(in)
	switch len(out) {
	case 0:
		return nil, true, nil
	case 1:
		if err, ok := out[0].Interface().(error); ok && err != nil {
			return nil, true, err
		}
		return out[0].Interface(), true, nil
	default:
		var result any
		if out[0].IsValid() {
			result = out[0].Interface()
		}
		if len(out) > 1 {
			if err, ok := out[1].Interface().(error); ok && err != nil {
				return result, true, err
			}
		}
		return result, true, nil
	}
}

func (r *secureCellLifecycleRuntime) deliveryLoop() {
	defer r.wg.Done()
	for {
		select {
		case task := <-r.queue:
			r.executeDelivery(task)
		case <-r.stopCh:
			return
		}
	}
}

func (r *secureCellLifecycleRuntime) executeDelivery(task secureCellWebhookDeliveryTask) {
	payload, err := json.Marshal(task.event)
	if err != nil {
		r.failDelivery(task.deliveryID, 0, err)
		return
	}

	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, task.endpoint, bytes.NewReader(payload))
		if err != nil {
			r.failDelivery(task.deliveryID, attempt, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Aethelred-Event-ID", task.event.EventID)
		if token := strings.TrimSpace(r.config.BearerToken); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if secret := strings.TrimSpace(r.config.HMACSecret); secret != "" {
			signature := computeSecureCellWebhookSignature(secret, payload)
			req.Header.Set("X-Aethelred-Signature", "sha256="+signature)
		}

		resp, err := r.client.Do(req)
		if err == nil && resp != nil && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			r.completeDelivery(task.deliveryID, attempt)
			return
		}
		statusErr := err
		if resp != nil {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			if statusErr == nil {
				statusErr = fmt.Errorf("webhook endpoint returned status %d", resp.StatusCode)
			}
		}
		r.failDelivery(task.deliveryID, attempt, statusErr)
		if attempt < r.config.MaxAttempts {
			time.Sleep(r.config.RetryBackoff * time.Duration(attempt))
		}
	}
}

func (r *secureCellLifecycleRuntime) recordAuditEvent(event securecellsintegration.SecureCellLifecycleEvent) {
	if r == nil || r.app == nil {
		return
	}
	logger := r.app.PouwKeeper.AuditLogger()
	ctx := safeAuditKeeperContext(r.app)
	if logger == nil || ctx == nil {
		return
	}
	sdkCtx, ok := ctx.(sdk.Context)
	if !ok {
		return
	}
	if sdkCtx.BlockHeight() <= 0 {
		sdkCtx = sdkCtx.WithBlockHeight(1)
	}
	category, severity := secureCellAuditClassification(event.Action)
	logger.Record(sdkCtx, category, severity, event.Action, firstNonEmpty(strings.TrimSpace(event.Actor), "system"), secureCellAuditDetails(event))
}

func (r *secureCellLifecycleRuntime) enqueueWebhookDeliveries(_ context.Context, event securecellsintegration.SecureCellLifecycleEvent) {
	if r == nil || len(r.config.Endpoints) == 0 || r.queue == nil {
		return
	}
	for _, endpoint := range r.config.Endpoints {
		record := secureCellWebhookDeliveryRecord{
			DeliveryID: fmt.Sprintf("%s:%x", event.EventID, sha256.Sum256([]byte(endpoint))),
			EventID:    event.EventID,
			CellID:     event.CellID,
			Action:     event.Action,
			Endpoint:   endpoint,
			Status:     secureCellWebhookDeliveryPending,
			CreatedAt:  time.Now().UTC(),
			UpdatedAt:  time.Now().UTC(),
		}
		r.storeDelivery(record)
		task := secureCellWebhookDeliveryTask{
			deliveryID: record.DeliveryID,
			endpoint:   endpoint,
			event:      event,
		}
		select {
		case r.queue <- task:
		default:
			r.failDelivery(record.DeliveryID, 0, fmt.Errorf("webhook delivery queue is full"))
		}
	}
}

func (r *secureCellLifecycleRuntime) storeDelivery(record secureCellWebhookDeliveryRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveries = append(r.deliveries, cloneSecureCellWebhookDelivery(record))
}

func (r *secureCellLifecycleRuntime) completeDelivery(deliveryID string, attempts int) {
	r.updateDelivery(deliveryID, func(record *secureCellWebhookDeliveryRecord) {
		now := time.Now().UTC()
		record.Status = secureCellWebhookDeliverySucceeded
		record.Attempts = attempts
		record.LastError = ""
		record.LastAttemptAt = &now
		record.DeliveredAt = &now
		record.UpdatedAt = now
	})
}

func (r *secureCellLifecycleRuntime) failDelivery(deliveryID string, attempts int, err error) {
	r.updateDelivery(deliveryID, func(record *secureCellWebhookDeliveryRecord) {
		now := time.Now().UTC()
		record.Status = secureCellWebhookDeliveryFailed
		record.Attempts = attempts
		record.LastAttemptAt = &now
		record.UpdatedAt = now
		if err != nil {
			record.LastError = err.Error()
		}
	})
}

func (r *secureCellLifecycleRuntime) updateDelivery(deliveryID string, mutate func(record *secureCellWebhookDeliveryRecord)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for idx := range r.deliveries {
		if r.deliveries[idx].DeliveryID != deliveryID {
			continue
		}
		mutate(&r.deliveries[idx])
		return
	}
}

func normalizeSecureCellWebhookConfig(config secureCellWebhookConfig) secureCellWebhookConfig {
	out := config
	out.Endpoints = parseSecureCellWebhookEndpoints(out.Endpoints)
	if out.Timeout <= 0 {
		out.Timeout = defaultSecureCellWebhookTimeout
	}
	if out.RetryBackoff <= 0 {
		out.RetryBackoff = defaultSecureCellWebhookRetryBackoff
	}
	if out.MaxAttempts <= 0 {
		out.MaxAttempts = defaultSecureCellWebhookMaxAttempts
	}
	if out.QueueSize <= 0 {
		out.QueueSize = defaultSecureCellWebhookQueueSize
	}
	if out.Workers <= 0 {
		out.Workers = defaultSecureCellWebhookWorkers
	}
	return out
}

func normalizeSecureCellExpirySweepInterval(interval time.Duration) time.Duration {
	if interval < 0 {
		return 0
	}
	if interval == 0 {
		return defaultSecureCellExpirySweepInterval
	}
	return interval
}

func resolveSecureCellWebhookConfig(appOpts servertypes.AppOptions) secureCellWebhookConfig {
	return secureCellWebhookConfig{
		Endpoints: parseSecureCellWebhookEndpointString(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_urls")),
			cast.ToString(appOpts.Get("secure_cells.webhook_urls")),
			os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_URLS"),
		)),
		BearerToken: strings.TrimSpace(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_bearer_token")),
			cast.ToString(appOpts.Get("secure_cells.webhook_bearer_token")),
			os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_BEARER_TOKEN"),
		)),
		HMACSecret: strings.TrimSpace(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_hmac_secret")),
			cast.ToString(appOpts.Get("secure_cells.webhook_hmac_secret")),
			os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_HMAC_SECRET"),
		)),
		Timeout:      parseOptionalDuration(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_timeout")), cast.ToString(appOpts.Get("secure_cells.webhook_timeout")), os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_TIMEOUT")), 0),
		RetryBackoff: parseOptionalDuration(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_retry_backoff")), cast.ToString(appOpts.Get("secure_cells.webhook_retry_backoff")), os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_RETRY_BACKOFF")), 0),
		MaxAttempts: cast.ToInt(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_max_attempts")),
			cast.ToString(appOpts.Get("secure_cells.webhook_max_attempts")),
			os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_MAX_ATTEMPTS"),
		)),
		QueueSize: cast.ToInt(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_queue_size")),
			cast.ToString(appOpts.Get("secure_cells.webhook_queue_size")),
			os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_QUEUE_SIZE"),
		)),
		Workers: cast.ToInt(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.secure_cells.webhook_workers")),
			cast.ToString(appOpts.Get("secure_cells.webhook_workers")),
			os.Getenv("AETHELRED_SECURE_CELLS_WEBHOOK_WORKERS"),
		)),
	}
}

func resolveSecureCellExpirySweepInterval(appOpts servertypes.AppOptions) time.Duration {
	raw := strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.expiry_sweep_interval")),
		cast.ToString(appOpts.Get("secure_cells.expiry_sweep_interval")),
		os.Getenv("AETHELRED_SECURE_CELLS_EXPIRY_SWEEP_INTERVAL"),
	))
	switch {
	case raw == "":
		return defaultSecureCellExpirySweepInterval
	case strings.EqualFold(raw, "off"), strings.EqualFold(raw, "disabled"), raw == "0":
		return 0
	default:
		duration := parseOptionalDuration(raw, defaultSecureCellExpirySweepInterval)
		if duration < 0 {
			return 0
		}
		if duration == 0 {
			return defaultSecureCellExpirySweepInterval
		}
		return duration
	}
}

func parseOptionalDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if strings.EqualFold(raw, "off") || strings.EqualFold(raw, "disabled") {
		return 0
	}
	if duration, err := time.ParseDuration(raw); err == nil {
		return duration
	}
	return cast.ToDuration(raw)
}

func parseSecureCellWebhookEndpointString(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	return parseSecureCellWebhookEndpoints(parts)
}

func parseSecureCellWebhookEndpoints(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func secureCellAuditClassification(action string) (pouwkeeper.AuditCategory, pouwkeeper.AuditSeverity) {
	switch action {
	case "secure_cell.member_quarantined", "secure_cell.session_quarantined", "secure_cell.session_thread_quarantined", "secure_cell.session_thread_decision_quarantined":
		return pouwkeeper.AuditCategorySecurity, pouwkeeper.AuditSeverityWarning
	case "secure_cell.member_revoked":
		return pouwkeeper.AuditCategorySecurity, pouwkeeper.AuditSeverityCritical
	case "secure_cell.paused", "secure_cell.terminated", "secure_cell.session_paused":
		return pouwkeeper.AuditCategoryGovernance, pouwkeeper.AuditSeverityWarning
	default:
		return pouwkeeper.AuditCategoryGovernance, pouwkeeper.AuditSeverityInfo
	}
}

func secureCellAuditDetails(event securecellsintegration.SecureCellLifecycleEvent) map[string]string {
	details := cloneSecureCellStringMap(event.Metadata)
	if details == nil {
		details = make(map[string]string)
	}
	details["workflow"] = "secure_cell"
	details["cell_id"] = event.CellID
	details["event_id"] = event.EventID
	details["cell_status"] = string(event.CellStatus)
	if event.TargetDID != "" {
		details["participant_did"] = event.TargetDID
	}
	if event.SessionID != "" {
		details["session_id"] = event.SessionID
	}
	if event.ThreadID != "" {
		details["thread_id"] = event.ThreadID
	}
	if event.DecisionID != "" {
		details["decision_id"] = event.DecisionID
	}
	if event.SessionExchangeID != "" {
		details["session_exchange_id"] = event.SessionExchangeID
	}
	if event.SharedOutputID != "" {
		details["shared_output_id"] = event.SharedOutputID
	}
	if event.ControlLedgerID != "" {
		details["control_ledger_id"] = event.ControlLedgerID
	}
	if event.ControlLedgerContentHash != "" {
		details["control_ledger_content_hash"] = event.ControlLedgerContentHash
	}
	if event.PortablePackageHash != "" {
		details["portable_package_hash"] = event.PortablePackageHash
	}
	if event.PolicyReceiptID != "" {
		details["policy_receipt_id"] = event.PolicyReceiptID
	}
	if event.SealID != "" {
		details["seal_id"] = event.SealID
	}
	return details
}

func listSecureCellAuditEvents(app *AethelredApp, filter secureCellAuditEventFilter) []secureCellAuditEventRecord {
	if app == nil || app.PouwKeeper.AuditLogger() == nil {
		return nil
	}
	records := app.PouwKeeper.AuditLogger().GetRecords()
	items := make([]secureCellAuditEventRecord, 0, len(records))
	for _, record := range records {
		if !strings.HasPrefix(record.Action, "secure_cell.") {
			continue
		}
		if filter.SinceSequence > 0 && record.Sequence < filter.SinceSequence {
			continue
		}
		if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(record.Details["cell_id"]), strings.TrimSpace(filter.CellID)) {
			continue
		}
		if filter.ParticipantDID != "" && !strings.EqualFold(strings.TrimSpace(record.Details["participant_did"]), strings.TrimSpace(filter.ParticipantDID)) {
			continue
		}
		if filter.ThreadID != "" && !strings.EqualFold(strings.TrimSpace(record.Details["thread_id"]), strings.TrimSpace(filter.ThreadID)) {
			continue
		}
		if filter.DecisionID != "" && !strings.EqualFold(strings.TrimSpace(record.Details["decision_id"]), strings.TrimSpace(filter.DecisionID)) {
			continue
		}
		if filter.Action != "" && !strings.EqualFold(strings.TrimSpace(record.Action), strings.TrimSpace(filter.Action)) {
			continue
		}
		if filter.Actor != "" && !strings.EqualFold(strings.TrimSpace(record.Actor), strings.TrimSpace(filter.Actor)) {
			continue
		}
		items = append(items, secureCellAuditEventRecord{
			Sequence:          record.Sequence,
			RecordHash:        record.RecordHash,
			BlockHeight:       record.BlockHeight,
			Timestamp:         record.Timestamp,
			Category:          record.Category,
			Severity:          record.Severity,
			Action:            record.Action,
			Actor:             record.Actor,
			CellID:            record.Details["cell_id"],
			EventID:           record.Details["event_id"],
			ParticipantDID:    record.Details["participant_did"],
			ThreadID:          record.Details["thread_id"],
			DecisionID:        record.Details["decision_id"],
			CellStatus:        record.Details["cell_status"],
			ControlLedgerID:   record.Details["control_ledger_id"],
			PortablePackageID: record.Details["portable_package_hash"],
			Details:           cloneSecureCellStringMap(record.Details),
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Sequence > items[j].Sequence
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items
}

func computeSecureCellWebhookSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func cloneSecureCellWebhookDelivery(in secureCellWebhookDeliveryRecord) secureCellWebhookDeliveryRecord {
	out := in
	out.LastAttemptAt = cloneSecureCellTimePtr(in.LastAttemptAt)
	out.DeliveredAt = cloneSecureCellTimePtr(in.DeliveredAt)
	return out
}

func cloneSecureCellStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneSecureCellTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	value := in.UTC()
	return &value
}

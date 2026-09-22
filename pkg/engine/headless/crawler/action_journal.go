package crawler

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
)

// actionOutcome captures the observable effect of one headless action without
// persisting response bodies or other potentially large page data.
type actionOutcome struct {
	Executed             bool
	StateCaptureFailed   bool
	BeforeURL            string
	AfterURL             string
	BeforeStateID        string
	AfterStateID         string
	DOMChanged           bool
	NetworkRequests      int
	NetworkFingerprint   string
	NetworkCaptureFailed bool
	PopupURLs            []string
	Popups               []actionPopupSnapshot
	CoverageKey          string
	OutcomeFingerprint   string
}

type actionPopupSnapshot struct {
	URL       string `json:"url,omitempty"`
	Title     string `json:"title,omitempty"`
	DOMSHA256 string `json:"dom_sha256,omitempty"`
	DOMPath   string `json:"dom_path,omitempty"`
}

type actionElementSummary struct {
	Tag         string                     `json:"tag,omitempty"`
	ID          string                     `json:"id,omitempty"`
	Classes     string                     `json:"classes,omitempty"`
	Text        string                     `json:"text,omitempty"`
	DocumentURL string                     `json:"document_url,omitempty"`
	Locator     []types.ElementLocatorStep `json:"locator,omitempty"`
	Attributes  map[string]string          `json:"attributes,omitempty"`
}

type actionJournalEvent struct {
	Timestamp            time.Time             `json:"timestamp"`
	Stage                string                `json:"stage"`
	Result               string                `json:"result,omitempty"`
	Reason               string                `json:"reason,omitempty"`
	Error                string                `json:"error,omitempty"`
	ActionType           types.ActionType      `json:"action_type,omitempty"`
	ActionID             string                `json:"action_id,omitempty"`
	Depth                int                   `json:"depth,omitempty"`
	OriginID             string                `json:"origin_id,omitempty"`
	Input                string                `json:"input,omitempty"`
	Element              *actionElementSummary `json:"element,omitempty"`
	BeforeURL            string                `json:"before_url,omitempty"`
	AfterURL             string                `json:"after_url,omitempty"`
	BeforeStateID        string                `json:"before_state_id,omitempty"`
	AfterStateID         string                `json:"after_state_id,omitempty"`
	DOMChanged           bool                  `json:"dom_changed,omitempty"`
	NetworkRequests      int                   `json:"network_requests,omitempty"`
	NetworkFingerprint   string                `json:"network_fingerprint,omitempty"`
	NetworkCaptureFailed bool                  `json:"network_capture_failed,omitempty"`
	PopupURLs            []string              `json:"popup_urls,omitempty"`
	Popups               []actionPopupSnapshot `json:"popups,omitempty"`
	SeedURL              string                `json:"seed_url,omitempty"`
	CoverageKey          string                `json:"coverage_key,omitempty"`
	OutcomeFingerprint   string                `json:"outcome_fingerprint,omitempty"`
	QueuedActions        int                   `json:"queued_actions,omitempty"`
	InventoryTruncated   bool                  `json:"inventory_truncated,omitempty"`
	InventoryVersion     int                   `json:"inventory_version,omitempty"`
	CandidateActions     int                   `json:"candidate_actions,omitempty"`
	InteractiveQueued    int                   `json:"interactive_queued_actions,omitempty"`
	DeferredActions      int                   `json:"deferred_actions,omitempty"`
	DeniedActions        int                   `json:"denied_actions,omitempty"`
	SkippedActions       int                   `json:"skipped_actions,omitempty"`
	DuplicateActions     int                   `json:"duplicate_actions,omitempty"`
	OmittedActions       int                   `json:"omitted_actions,omitempty"`
}

type actionJournal struct {
	file             *os.File
	writer           *bufio.Writer
	baseDir          string
	mu               sync.Mutex
	eventsSinceFlush int
	lastFlush        time.Time
}

func newActionJournal(path string) (*actionJournal, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &actionJournal{
		file:      file,
		writer:    bufio.NewWriterSize(file, 256*1024),
		baseDir:   filepath.Dir(path),
		lastFlush: time.Now(),
	}, nil
}

func (j *actionJournal) storePopupDOM(rawURL string, title string, html string) actionPopupSnapshot {
	snapshot := actionPopupSnapshot{URL: rawURL, Title: title}
	if j == nil || html == "" {
		return snapshot
	}
	sum := sha256.Sum256([]byte(html))
	snapshot.DOMSHA256 = fmt.Sprintf("%x", sum[:])
	relative := filepath.Join(
		"action-popups",
		"sha256",
		snapshot.DOMSHA256[:2],
		snapshot.DOMSHA256+".html",
	)
	absolute := filepath.Join(j.baseDir, relative)
	if err := os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return snapshot
	}
	if err := os.WriteFile(absolute, []byte(html), 0600); err == nil {
		snapshot.DOMPath = filepath.ToSlash(relative)
	}
	return snapshot
}

func (j *actionJournal) Close() error {
	if j == nil || j.file == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.writer != nil {
		if err := j.writer.Flush(); err != nil {
			_ = j.file.Close()
			j.file = nil
			return err
		}
	}
	err := j.file.Close()
	j.file = nil
	j.writer = nil
	return err
}

func (j *actionJournal) write(event actionJournalEvent) error {
	if j == nil || j.file == nil {
		return nil
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.writer == nil {
		return os.ErrClosed
	}
	if _, err = j.writer.Write(data); err != nil {
		return err
	}
	j.eventsSinceFlush++
	// Discovery can contain tens of thousands of controls. Batch those writes,
	// while keeping state/attempt lifecycle evidence immediately visible to the
	// parent watchdog and resilient to an interrupted worker.
	force := event.Stage != "discovered"
	if force || j.eventsSinceFlush >= 128 || time.Since(j.lastFlush) >= time.Second {
		if err := j.writer.Flush(); err != nil {
			return err
		}
		j.eventsSinceFlush = 0
		j.lastFlush = time.Now()
	}
	return nil
}

func summarizeActionElement(element *types.HTMLElement) *actionElementSummary {
	if element == nil {
		return nil
	}
	attributes := make(map[string]string)
	for _, key := range []string{
		"name", "type", "href", "role", "title", "aria-label",
		"aria-labelledby", "data-testid", "data-test", "data-cy",
	} {
		if value := strings.TrimSpace(element.Attributes[key]); value != "" {
			attributes[key] = value
		}
	}
	if len(attributes) == 0 {
		attributes = nil
	}
	text := strings.Join(strings.Fields(element.TextContent), " ")
	if len(text) > 300 {
		text = text[:300]
	}
	return &actionElementSummary{
		Tag:         element.TagName,
		ID:          element.ID,
		Classes:     element.Classes,
		Text:        text,
		DocumentURL: element.DocumentURL,
		Locator:     element.DeepLocator,
		Attributes:  attributes,
	}
}

func (c *Crawler) recordActionEvent(
	stage string,
	result string,
	reason string,
	action *types.Action,
	outcome *actionOutcome,
	actionErr error,
) {
	if c.actionJournal == nil {
		return
	}
	event := actionJournalEvent{
		Timestamp: time.Now().UTC(),
		Stage:     stage,
		Result:    result,
		Reason:    reason,
		SeedURL:   c.seedURL,
	}
	if action != nil {
		event.ActionType = action.Type
		event.ActionID = action.Hash()
		event.Depth = action.Depth
		event.OriginID = action.OriginID
		event.Input = action.Input
		event.Element = summarizeActionElement(action.Element)
	}
	if outcome != nil {
		event.BeforeURL = outcome.BeforeURL
		event.AfterURL = outcome.AfterURL
		event.BeforeStateID = outcome.BeforeStateID
		event.AfterStateID = outcome.AfterStateID
		event.DOMChanged = outcome.DOMChanged
		event.NetworkRequests = outcome.NetworkRequests
		event.NetworkFingerprint = outcome.NetworkFingerprint
		event.NetworkCaptureFailed = outcome.NetworkCaptureFailed
		event.PopupURLs = outcome.PopupURLs
		event.Popups = outcome.Popups
		event.CoverageKey = outcome.CoverageKey
		event.OutcomeFingerprint = outcome.OutcomeFingerprint
	}
	if actionErr != nil {
		event.Error = actionErr.Error()
	}
	if err := c.actionJournal.write(event); err != nil {
		c.logger.Warn("Failed to write action journal", "error", err)
	}
}

type stateActionInventory struct {
	Candidates        int
	Queued            int
	InteractiveQueued int
	Deferred          int
	Denied            int
	Skipped           int
	Duplicates        int
	Omitted           int
	Truncated         bool
}

func (c *Crawler) recordStateInventory(state *types.PageState, inventory stateActionInventory) {
	if c.actionJournal == nil || state == nil {
		return
	}
	event := actionJournalEvent{
		Timestamp:          time.Now().UTC(),
		Stage:              "state",
		Result:             "inventoried",
		SeedURL:            c.seedURL,
		AfterURL:           state.URL,
		AfterStateID:       state.UniqueID,
		QueuedActions:      inventory.Queued,
		InventoryTruncated: inventory.Truncated,
		InventoryVersion:   2,
		CandidateActions:   inventory.Candidates,
		InteractiveQueued:  inventory.InteractiveQueued,
		DeferredActions:    inventory.Deferred,
		DeniedActions:      inventory.Denied,
		SkippedActions:     inventory.Skipped,
		DuplicateActions:   inventory.Duplicates,
		OmittedActions:     inventory.Omitted,
	}
	if err := c.actionJournal.write(event); err != nil {
		c.logger.Warn("Failed to write state inventory", "error", err)
	}
}

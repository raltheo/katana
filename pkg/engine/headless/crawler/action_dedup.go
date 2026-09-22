package crawler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
)

var actionCoverageKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type actionDedupRecord struct {
	CoverageKey string `json:"coverage_key"`
}

// loadActionDedupKeys accepts JSONL records so the producer can retain audit
// metadata next to each key. A raw SHA-256 per line is also accepted for
// simple integrations. The file is intentionally read-only: deciding when an
// observation is sufficiently confirmed belongs to the caller.
func loadActionDedupKeys(path string) (map[string]struct{}, error) {
	keys := make(map[string]struct{})
	if strings.TrimSpace(path) == "" {
		return keys, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key := line
		if strings.HasPrefix(line, "{") {
			var record actionDedupRecord
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				return nil, fmt.Errorf("line %d: invalid JSON: %w", lineNumber, err)
			}
			key = strings.TrimSpace(record.CoverageKey)
		}
		key = strings.ToLower(key)
		if !actionCoverageKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid semantic action coverage key", lineNumber)
		}
		keys[key] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// actionCoverageKey is deliberately strict. Two actions only share a key when
// they originate from the exact same normalized page state, at the exact same
// URL, and expose the same stable semantic control identity. Generated DOM
// IDs, classes and locators are excluded by semanticActionStateKey.
func (c *Crawler) actionCoverageKey(action *types.Action) string {
	if action == nil || action.Type == types.ActionTypeLoadURL || action.OriginID == "" || c.crawlGraph == nil {
		return ""
	}
	actionKey := semanticActionStateKey(action)
	if actionKey == "" {
		return ""
	}
	origin, err := c.crawlGraph.GetPageState(action.OriginID)
	if err != nil || origin == nil || origin.UniqueID == "" || origin.URL == "" {
		return ""
	}
	return sha256Hash(strings.Join([]string{
		"version:1",
		"url:" + origin.URL,
		"state:" + origin.UniqueID,
		"actions:" + origin.ActionSignature,
		"action:" + actionKey,
	}, "\n"))
}

// actionOutcomeFingerprint records the exact normalized state reached by a
// successful action. Missing state evidence yields no fingerprint, which keeps
// deduplication fail-open for technically uncertain actions.
func (c *Crawler) actionOutcomeFingerprint(outcome *actionOutcome) string {
	if outcome == nil || !outcome.Executed || outcome.StateCaptureFailed ||
		outcome.NetworkCaptureFailed || outcome.NetworkFingerprint == "" ||
		outcome.AfterStateID == "" || c.crawlGraph == nil {
		return ""
	}
	after, err := c.crawlGraph.GetPageState(outcome.AfterStateID)
	if err != nil || after == nil || after.UniqueID == "" || after.URL == "" {
		return ""
	}

	popupKeys := make([]string, 0, len(outcome.Popups)+len(outcome.PopupURLs))
	for _, popup := range outcome.Popups {
		popupKeys = append(popupKeys, popup.URL+"|"+popup.DOMSHA256)
	}
	if len(outcome.Popups) == 0 {
		popupKeys = append(popupKeys, outcome.PopupURLs...)
	}
	sort.Strings(popupKeys)

	return sha256Hash(strings.Join([]string{
		"version:1",
		"url:" + after.URL,
		"state:" + after.UniqueID,
		"actions:" + after.ActionSignature,
		"dom_changed:" + strconv.FormatBool(outcome.DOMChanged),
		"network:" + outcome.NetworkFingerprint,
		"popups:" + strings.Join(popupKeys, "\x00"),
	}, "\n"))
}

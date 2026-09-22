package crawler

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/stretchr/testify/require"
)

func TestConfirmedSemanticActionIsSkippedOnLaterSeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = writer.Write([]byte(`<!doctype html><html><body>
			<button id="open" type="button" onclick="document.getElementById('result').textContent='clicked'">Open panel</button>
			<div id="result"></div>
		</body></html>`))
	}))
	defer server.Close()

	newCrawler := func(actionLog string, dedupFile string) *Crawler {
		crawler, err := New(Options{
			MaxBrowsers:        1,
			MaxDepth:           2,
			MaxActionDepth:     2,
			MaxActionsPerState: 10,
			MaxActionsPerCrawl: 10,
			MaxFailureCount:    3,
			ActionLogFile:      actionLog,
			ActionDedupFile:    dedupFile,
			PageMaxTimeout:     3 * time.Second,
			PageLoadStrategy:   "load",
			NoSandbox:          true,
			Logger:             slog.Default(),
			ScopeValidator: func(rawURL string) bool {
				return strings.HasPrefix(rawURL, server.URL)
			},
		})
		require.NoError(t, err)
		return crawler
	}

	directory := t.TempDir()
	firstLog := filepath.Join(directory, "first-actions.jsonl")
	first := newCrawler(firstLog, "")
	require.NoError(t, first.Crawl(server.URL))
	first.Close()

	coverageKey := ""
	coveredStateID := ""
	inventoriedStates := make(map[string]struct{})
	firstFile, err := os.Open(firstLog)
	require.NoError(t, err)
	firstScanner := bufio.NewScanner(firstFile)
	for firstScanner.Scan() {
		var event actionJournalEvent
		require.NoError(t, json.Unmarshal(firstScanner.Bytes(), &event))
		if event.Stage == "state" && event.Result == "inventoried" {
			inventoriedStates[event.AfterStateID] = struct{}{}
		}
		if event.Stage == "attempt" && event.Result == "success" &&
			event.ActionType == types.ActionTypeLeftClick {
			coverageKey = event.CoverageKey
			coveredStateID = event.AfterStateID
		}
	}
	require.NoError(t, firstScanner.Err())
	require.NoError(t, firstFile.Close())
	require.Regexp(t, actionCoverageKeyPattern, coverageKey)
	require.NotEmpty(t, coveredStateID)
	require.Contains(t, inventoriedStates, coveredStateID)

	dedupFile := filepath.Join(directory, "confirmed-actions.jsonl")
	require.NoError(t, os.WriteFile(
		dedupFile,
		[]byte(`{"coverage_key":"`+coverageKey+`"}`+"\n"),
		0600,
	))
	secondLog := filepath.Join(directory, "second-actions.jsonl")
	second := newCrawler(secondLog, dedupFile)
	require.NoError(t, second.Crawl(server.URL))
	second.Close()

	deduplicated := 0
	succeeded := 0
	secondFile, err := os.Open(secondLog)
	require.NoError(t, err)
	defer secondFile.Close()
	secondScanner := bufio.NewScanner(secondFile)
	for secondScanner.Scan() {
		var event actionJournalEvent
		require.NoError(t, json.Unmarshal(secondScanner.Bytes(), &event))
		if event.Stage != "attempt" || event.ActionType != types.ActionTypeLeftClick {
			continue
		}
		switch event.Result {
		case "deduplicated":
			deduplicated++
			require.Equal(t, coverageKey, event.CoverageKey)
		case "success":
			succeeded++
		}
	}
	require.NoError(t, secondScanner.Err())
	require.Equal(t, 1, deduplicated)
	require.Zero(t, succeeded)
}

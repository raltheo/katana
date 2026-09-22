package crawler

import (
	"bufio"
	"encoding/json"
	"fmt"
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

func TestActionRuntimeLimitRetriesThenContinues(t *testing.T) {
	skipIfNoCrawlerBrowser(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!doctype html><html><body>
			<button onclick="const end=Date.now()+5000;while(Date.now()<end){}">Slow action</button>
		</body></html>`)
	}))
	defer server.Close()

	actionLog := filepath.Join(t.TempDir(), "actions.jsonl")
	crawler, err := New(Options{
		MaxBrowsers:             1,
		MaxDepth:                1,
		MaxActionDepth:          1,
		MaxActionsPerCrawl:      5,
		MaxActionRuntime:        500 * time.Millisecond,
		MaxActionRetries:        1,
		MaxFailureCount:         10,
		ContinueOnActionFailure: true,
		ActionLogFile:           actionLog,
		PageMaxTimeout:          3 * time.Second,
		PageLoadStrategy:        "load",
		NoSandbox:               true,
		Logger:                  slog.Default(),
		ScopeValidator: func(rawURL string) bool {
			return strings.HasPrefix(rawURL, server.URL)
		},
	})
	require.NoError(t, err)
	started := time.Now()
	require.NoError(t, crawler.Crawl(server.URL))
	crawler.Close()
	// The local-browser fixture pays for two complete Chrome launches because a
	// poisoned internal browser is discarded with its page. External -cwu runs
	// reuse Chrome and only recreate the worker tab.
	require.Less(t, time.Since(started), 15*time.Second)

	file, err := os.Open(actionLog)
	require.NoError(t, err)
	defer file.Close()
	retries := 0
	failures := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event actionJournalEvent
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		if event.Stage != "attempt" || event.ActionType != types.ActionTypeLeftClick {
			continue
		}
		switch event.Result {
		case "retry":
			retries++
		case "failed":
			failures++
			require.Equal(t, "action runtime limit reached", event.Reason)
		}
	}
	require.NoError(t, scanner.Err())
	require.Equal(t, 1, retries)
	require.Equal(t, 1, failures)
}

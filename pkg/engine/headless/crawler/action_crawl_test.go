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
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipIfNoCrawlerBrowser(t *testing.T) {
	t.Helper()
	path, _ := launcher.LookPath()
	if path == "" {
		t.Skip("chrome/chromium not found, skipping crawler browser test")
	}
}

func TestActionCrawlerContinuesRestoresBranchesAndCapturesPopup(t *testing.T) {
	skipIfNoCrawlerBrowser(t)
	var firstHits atomic.Int32
	var secondHits atomic.Int32
	var childHits atomic.Int32
	var popupHits atomic.Int32
	var pointerFallbackHits atomic.Int32
	var rootLoads atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		generation := rootLoads.Add(1)
		page := `<!doctype html><html><head><title>Action fixture</title>
			<style>
				#covered { position: relative; width: 320px; height: 100px; overflow: hidden; }
				#shield { position: absolute; inset: 0; z-index: 10; background: rgba(0,0,0,.01); }
				#panel { display: none; }
			</style></head><body>
			<div id="covered">
				<div id="shield"></div>
				<button class="covered-action">Covered 01</button>
				<button class="covered-action">Covered 02</button>
				<button class="covered-action">Covered 03</button>
				<button class="covered-action">Covered 04</button>
				<button class="covered-action">Covered 05</button>
				<button class="covered-action">Covered 06</button>
				<button class="covered-action">Covered 07</button>
				<button class="covered-action">Covered 08</button>
				<button class="covered-action">Covered 09</button>
				<button class="covered-action">Covered 10</button>
				<button class="covered-action">Covered 11</button>
				<button class="covered-action">Covered 12</button>
			</div>
			<div id="__DYNAMIC_ANCESTOR_ID__">
			<button class="branch-action" onclick="
				(new Image()).src='/hit/first';
				document.querySelector('#covered').hidden=true;
				document.querySelectorAll('.branch-action,#popup-link').forEach((e)=>e.hidden=true);
				document.body.insertAdjacentHTML('beforeend','<p>First branch state</p>');
			">First branch</button>
			<button class="branch-action" onclick="
				(new Image()).src='/hit/second';
				document.querySelector('#covered').hidden=true;
				document.querySelectorAll('.branch-action,#popup-link').forEach((e)=>e.hidden=true);
				document.body.insertAdjacentHTML('beforeend','<p>Second branch state</p>');
			">Second branch</button>
			<button class="branch-action" onclick="
				document.querySelector('#covered').hidden=true;
				document.querySelectorAll('.branch-action,#popup-link').forEach((e)=>e.hidden=true);
				document.querySelector('#panel').style.display='block';
				document.querySelector('#panel').innerHTML='<button id=&quot;child-action&quot; onclick=&quot;(new Image()).src=\'/hit/child\';this.hidden=true;&quot;>Nested child</button>';
			">Open menu</button>
			<div id="panel"></div>
			<a id="popup-link" href="/popup" target="_blank">Open popup</a>
			<a id="pointer-fallback" href="/pointer-fallback" style="pointer-events:none">Deferred route</a>
			</div>
		</body></html>`
		page = strings.Replace(
			page,
			"__DYNAMIC_ANCESTOR_ID__",
			fmt.Sprintf("6a3cdb1e-55fd-4980-8dde-fa99b8cb6c%02d", generation),
			1,
		)
		_, _ = fmt.Fprint(w, page)
	})
	mux.HandleFunc("/hit/first", func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/hit/second", func(w http.ResponseWriter, _ *http.Request) {
		secondHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/hit/child", func(w http.ResponseWriter, _ *http.Request) {
		childHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/popup", func(w http.ResponseWriter, _ *http.Request) {
		popupHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!doctype html><html><body><h1>Popup evidence</h1></body></html>`)
	})
	mux.HandleFunc("/pointer-fallback", func(w http.ResponseWriter, _ *http.Request) {
		pointerFallbackHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!doctype html><html><body><h1>Pointer fallback evidence</h1></body></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	actionLog := filepath.Join(t.TempDir(), "actions.jsonl")
	crawler, err := New(Options{
		MaxBrowsers:             1,
		MaxDepth:                1,
		MaxActionDepth:          3,
		MaxActionsPerState:      100,
		MaxActionsPerCrawl:      100,
		MaxFailureCount:         10,
		ContinueOnActionFailure: true,
		ActionPreflightTimeout:  2 * time.Second,
		ActionSignalTimeout:     500 * time.Millisecond,
		ActionQuietPeriod:       100 * time.Millisecond,
		CaptureNewTabs:          true,
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
	require.NoError(t, crawler.Crawl(server.URL))
	crawler.Close()

	hitsReady := assert.Eventuallyf(t, func() bool {
		return firstHits.Load() > 0 && secondHits.Load() > 0 && childHits.Load() > 0 && popupHits.Load() > 0 && pointerFallbackHits.Load() > 0
	}, 3*time.Second, 25*time.Millisecond, "hits: first=%d second=%d child=%d popup=%d fallback=%d roots=%d",
		firstHits.Load(), secondHits.Load(), childHits.Load(), popupHits.Load(), pointerFallbackHits.Load(), rootLoads.Load())
	if !hitsReady {
		if data, readErr := os.ReadFile(actionLog); readErr == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "child-action") || strings.Contains(line, "Open menu") {
					t.Log(line)
				}
			}
		}
		t.FailNow()
	}
	require.Greater(t, rootLoads.Load(), int32(1), "sibling restoration should survive regenerated ancestor IDs")

	file, err := os.Open(actionLog)
	require.NoError(t, err)
	defer file.Close()
	successfulClicks := 0
	failedClicks := 0
	deferredClicks := 0
	deferredByAction := make(map[string]int)
	popupCaptured := false
	popupAttachedToAction := false
	popupQueuedWithOrigin := false
	popupDOMPath := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event actionJournalEvent
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		if event.Stage == "attempt" && event.ActionType == types.ActionTypeLeftClick {
			switch event.Result {
			case "success":
				successfulClicks++
				require.NotEmpty(t, event.SeedURL)
				require.NotEmpty(t, event.NetworkFingerprint)
				require.False(t, event.NetworkCaptureFailed)
				require.Regexp(t, actionCoverageKeyPattern, event.CoverageKey)
				require.Regexp(t, actionCoverageKeyPattern, event.OutcomeFingerprint)
			case "failed":
				failedClicks++
			case "deferred":
				deferredClicks++
				deferredByAction[event.ActionID]++
			}
		}
		if event.Stage == "popup" && event.Result == "captured" && len(event.Popups) > 0 {
			popupCaptured = true
			popupDOMPath = event.Popups[0].DOMPath
		}
		if event.Stage == "popup" && event.Result == "queued" && event.OriginID != "" {
			popupQueuedWithOrigin = true
		}
		if event.Stage == "attempt" && event.Result == "success" && len(event.Popups) > 0 {
			popupAttachedToAction = true
		}
	}
	require.NoError(t, scanner.Err())
	require.GreaterOrEqual(t, failedClicks, 10, "covered controls should exceed the historical failure cutoff")
	require.GreaterOrEqual(t, deferredClicks, 10, "stale targets should receive one deferred retry")
	for actionID, count := range deferredByAction {
		require.Equal(t, 1, count, "action %s must be deferred at most once", actionID)
	}
	require.GreaterOrEqual(t, successfulClicks, 4, "sibling, nested and popup actions should remain reachable")
	require.True(t, popupCaptured)
	require.True(t, popupAttachedToAction)
	require.True(t, popupQueuedWithOrigin)
	require.NotEmpty(t, popupDOMPath)
	_, err = os.Stat(filepath.Join(filepath.Dir(actionLog), filepath.FromSlash(popupDOMPath)))
	require.NoError(t, err)
}

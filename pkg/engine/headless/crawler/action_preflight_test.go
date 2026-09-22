package crawler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/stretchr/testify/require"
)

func TestClickPreflightFastRejectsThenAllowsRecoveredTarget(t *testing.T) {
	skipIfNoCrawlerBrowser(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<!doctype html><html><head><style>
			#wrap { position: relative; width: 240px; height: 80px; }
			#shield { position: absolute; inset: 0; z-index: 10; }
		</style></head><body>
			<div id="wrap">
				<div id="shield"></div>
				<button id="target" onclick="this.dataset.clicked='yes'">Target</button>
			</div>
		</body></html>`)
	}))
	defer server.Close()

	crawler, err := New(Options{
		MaxBrowsers:            1,
		PageMaxTimeout:         3 * time.Second,
		ActionPreflightTimeout: 300 * time.Millisecond,
		ActionSignalTimeout:    300 * time.Millisecond,
		ActionQuietPeriod:      100 * time.Millisecond,
		DOMWaitTime:            2,
		PageLoadStrategy:       "adaptive",
		NoSandbox:              true,
		Logger:                 slog.Default(),
	})
	require.NoError(t, err)
	defer crawler.Close()
	page, err := crawler.launcher.GetPageFromPool()
	require.NoError(t, err)
	require.NoError(t, page.Navigate(server.URL))
	require.NoError(t, page.WaitLoad())

	navigations, err := page.FindNavigations()
	require.NoError(t, err)
	var action *types.Action
	for _, candidate := range navigations {
		if candidate.Element != nil && candidate.Element.ID == "target" {
			action = candidate
			break
		}
	}
	require.NotNil(t, action)

	started := time.Now()
	err = crawler.dispatchCrawlAction(action, page)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrActionPreflightUnavailable))
	require.Less(t, time.Since(started), time.Second)

	_, err = page.Eval(`() => document.querySelector('#shield').remove()`)
	require.NoError(t, err)
	require.NoError(t, crawler.dispatchCrawlAction(action, page))
	clicked, err := page.Eval(`() => document.querySelector('#target').dataset.clicked`)
	require.NoError(t, err)
	require.Equal(t, "yes", clicked.Value.Str())
	crawler.launcher.PutBrowserToPool(page)
}

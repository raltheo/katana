package browser

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/stretchr/testify/require"
)

// startSPAServer spins up a test HTTP server whose index page opens an
// SSE stream that never closes, mimicking real-world SPAs with persistent
// connections (analytics, chat, live updates). Network-idle strategies
// can't finish on pages like this because there's always traffic in flight.
func startSPAServer(t *testing.T) string {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>SPA Test</title></head>
<body>
  <a href="/page1">Page 1</a>
  <a href="/page2">Page 2</a>
  <a href="/api/data">API</a>
  <script>
    const evtSource = new EventSource("/stream");
    evtSource.onmessage = function(e) {};
  </script>
</body>
</html>`)
	})

	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(500 * time.Millisecond):
				_, _ = fmt.Fprintf(w, "data: keepalive\n\n")
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body><a href="/page3">Page 3</a></body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body>Page 2</body></html>`)
	})
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: mux}
	go server.Serve(listener) //nolint:errcheck
	t.Cleanup(func() { server.Close() })

	return fmt.Sprintf("http://%s", listener.Addr().String())
}

func skipIfNoBrowser(t *testing.T) {
	t.Helper()
	path, _ := launcher.LookPath()
	if path == "" {
		t.Skip("chrome/chromium not found, skipping browser test")
	}
}

// TestPageLoadStrategyWithSPA hits a local SPA whose index keeps an SSE
// connection open forever. Each subtest picks a different page-load strategy
// and checks that the crawl finishes in a reasonable time with the right HTML.
func TestPageLoadStrategyWithSPA(t *testing.T) {
	skipIfNoBrowser(t)
	baseURL := startSPAServer(t)

	t.Run("none strategy returns immediately", func(t *testing.T) {
		l, err := NewLauncher(LauncherOptions{
			MaxBrowsers:      1,
			PageLoadStrategy: "none",
			NoSandbox:        true,
		})
		require.NoError(t, err)
		defer l.Close()

		bp, err := l.GetPageFromPool()
		require.NoError(t, err)

		start := time.Now()
		err = bp.Navigate(baseURL)
		require.NoError(t, err)
		err = bp.WaitPageLoadHeurisitics()
		require.NoError(t, err)
		elapsed := time.Since(start)

		require.Less(t, elapsed, 10*time.Second, "none strategy should return almost immediately")
		l.PutBrowserToPool(bp)
	})

	t.Run("domcontentloaded strategy completes without hanging on SSE", func(t *testing.T) {
		l, err := NewLauncher(LauncherOptions{
			MaxBrowsers:      1,
			PageLoadStrategy: "domcontentloaded",
			DOMWaitTime:      1,
			NoSandbox:        true,
		})
		require.NoError(t, err)
		defer l.Close()

		bp, err := l.GetPageFromPool()
		require.NoError(t, err)

		start := time.Now()
		err = bp.Navigate(baseURL)
		require.NoError(t, err)
		err = bp.WaitPageLoadHeurisitics()
		require.NoError(t, err)
		elapsed := time.Since(start)

		// Should complete in ~1-2s (DOMWaitTime=1), not hang on SSE stream.
		// Relaxed to 15s to accommodate slow CI runners (Windows).
		require.Less(t, elapsed, 15*time.Second, "domcontentloaded should not hang on continuous network activity")

		html, err := bp.HTML()
		require.NoError(t, err)
		require.Contains(t, html, "Page 1", "page content should be loaded")
		require.Contains(t, html, "Page 2", "page content should be loaded")

		l.PutBrowserToPool(bp)
	})

	t.Run("load strategy completes on SPA with SSE", func(t *testing.T) {
		l, err := NewLauncher(LauncherOptions{
			MaxBrowsers:      1,
			PageLoadStrategy: "load",
			NoSandbox:        true,
		})
		require.NoError(t, err)
		defer l.Close()

		bp, err := l.GetPageFromPool()
		require.NoError(t, err)

		start := time.Now()
		err = bp.Navigate(baseURL)
		require.NoError(t, err)
		err = bp.WaitPageLoadHeurisitics()
		require.NoError(t, err)
		elapsed := time.Since(start)

		require.Less(t, elapsed, 20*time.Second, "load strategy should complete within timeout")

		html, err := bp.HTML()
		require.NoError(t, err)
		require.Contains(t, html, "Page 1")

		l.PutBrowserToPool(bp)
	})

	t.Run("heuristic strategy completes on SPA with SSE", func(t *testing.T) {
		l, err := NewLauncher(LauncherOptions{
			MaxBrowsers:      1,
			PageLoadStrategy: "heuristic",
			NoSandbox:        true,
		})
		require.NoError(t, err)
		defer l.Close()

		bp, err := l.GetPageFromPool()
		require.NoError(t, err)

		start := time.Now()
		err = bp.Navigate(baseURL)
		require.NoError(t, err)
		err = bp.WaitPageLoadHeurisitics()
		require.NoError(t, err)
		elapsed := time.Since(start)

		require.Less(t, elapsed, 20*time.Second, "heuristic should complete within timeout")

		html, err := bp.HTML()
		require.NoError(t, err)
		require.Contains(t, html, "Page 1")

		l.PutBrowserToPool(bp)
	})
}

// TestDOMWaitTimeIsRespected makes sure a larger DOMWaitTime value
// actually makes the domcontentloaded strategy wait longer.
func TestDOMWaitTimeIsRespected(t *testing.T) {
	skipIfNoBrowser(t)
	baseURL := startSPAServer(t)

	t.Run("shorter DOMWaitTime finishes faster", func(t *testing.T) {
		l, err := NewLauncher(LauncherOptions{
			MaxBrowsers:      1,
			PageLoadStrategy: "domcontentloaded",
			DOMWaitTime:      1,
			NoSandbox:        true,
		})
		require.NoError(t, err)
		defer l.Close()

		bp, err := l.GetPageFromPool()
		require.NoError(t, err)

		start := time.Now()
		err = bp.Navigate(baseURL)
		require.NoError(t, err)
		err = bp.WaitPageLoadHeurisitics()
		require.NoError(t, err)
		shortElapsed := time.Since(start)

		l.PutBrowserToPool(bp)

		l2, err := NewLauncher(LauncherOptions{
			MaxBrowsers:      1,
			PageLoadStrategy: "domcontentloaded",
			DOMWaitTime:      4,
			NoSandbox:        true,
		})
		require.NoError(t, err)
		defer l2.Close()

		bp2, err := l2.GetPageFromPool()
		require.NoError(t, err)

		start = time.Now()
		err = bp2.Navigate(baseURL)
		require.NoError(t, err)
		err = bp2.WaitPageLoadHeurisitics()
		require.NoError(t, err)
		longElapsed := time.Since(start)

		l2.PutBrowserToPool(bp2)

		require.Greater(t, longElapsed, shortElapsed, "DOMWaitTime=4 should take longer than DOMWaitTime=1")
		require.Greater(t, longElapsed, 3*time.Second, "DOMWaitTime=4 should wait at least ~4 seconds")
	})
}

func TestAdaptiveStrategyWaitsForDelayedSPAAndScrolls(t *testing.T) {
	skipIfNoBrowser(t)
	var apiHits atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!doctype html><html><body><div id="app"></div><script>
			setTimeout(async () => {
				const response = await fetch('/api/data');
				const data = await response.json();
				document.querySelector('#app').innerHTML =
					'<main style="height:6000px"><h1>' + data.title +
					'</h1><button id="primary">Open</button>' +
					'<div id="nested" style="height:100px;overflow-y:auto">' +
					'<div style="height:1500px">Nested content</div></div></main>';
				const nested = document.querySelector('#nested');
				nested.addEventListener('scroll', async () => {
					if (nested.scrollTop > 300 && !document.querySelector('#nested-lazy')) {
						const response = await fetch('/api/nested');
						const data = await response.json();
						const button = document.createElement('button');
						button.id = 'nested-lazy';
						button.textContent = data.label;
						nested.appendChild(button);
					}
				});
			}, 350);
			window.addEventListener('scroll', async () => {
				if (window.scrollY > 500 && !document.querySelector('#lazy')) {
					const response = await fetch('/api/lazy');
					const data = await response.json();
					const button = document.createElement('button');
					button.id = 'lazy';
					button.textContent = data.label;
					document.querySelector('#app').appendChild(button);
				}
			});
		</script></body></html>`)
	})
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"title":"Rendered route"}`)
	})
	mux.HandleFunc("/api/lazy", func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"label":"Lazy action"}`)
	})
	mux.HandleFunc("/api/nested", func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"label":"Nested lazy action"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	launcher, err := NewLauncher(LauncherOptions{
		MaxBrowsers:      1,
		PageLoadStrategy: "adaptive",
		DOMWaitTime:      8,
		AutomaticScroll:  true,
		ScrollStep:       700,
		ScrollDelay:      20,
		MaxScrollSteps:   20,
		NoSandbox:        true,
	})
	require.NoError(t, err)
	defer launcher.Close()

	page, err := launcher.GetPageFromPool()
	require.NoError(t, err)
	require.NoError(t, page.Navigate(server.URL))
	start := time.Now()
	require.NoError(t, page.WaitPageLoadHeurisitics())
	elapsed := time.Since(start)

	html, err := page.HTML()
	require.NoError(t, err)
	require.Contains(t, html, "Rendered route")
	require.Contains(t, html, "Lazy action")
	require.Contains(t, html, "Nested lazy action")
	require.GreaterOrEqual(t, apiHits.Load(), int32(3))
	require.Greater(t, elapsed, 2*time.Second)
	require.Less(t, elapsed, 8*time.Second)

	steps, err := page.Eval(`() => Number(window.__katanaAutoScrollSteps || 0)`)
	require.NoError(t, err)
	require.Greater(t, steps.Value.Int(), 0)
	launcher.PutBrowserToPool(page)
}

func TestAutomaticScrollDoesNotDependOnAnimationFrames(t *testing.T) {
	skipIfNoBrowser(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body style="height:4000px"><main>content</main></body></html>`)
	}))
	defer server.Close()

	launcher, err := NewLauncher(LauncherOptions{
		MaxBrowsers:     1,
		AutomaticScroll: true,
		ScrollStep:      700,
		ScrollDelay:     1,
		MaxScrollSteps:  1,
		NoSandbox:       true,
	})
	require.NoError(t, err)
	defer launcher.Close()

	page, err := launcher.GetPageFromPool()
	require.NoError(t, err)
	require.NoError(t, page.Navigate(server.URL))
	require.NoError(t, page.WaitLoad())
	_, err = page.Eval(`() => { window.requestAnimationFrame = () => 0; }`)
	require.NoError(t, err)

	started := time.Now()
	require.NoError(t, page.automaticScroll(3*time.Second))
	require.Less(t, time.Since(started), 3*time.Second)
	launcher.PutBrowserToPool(page)
}

func TestAdaptiveWaitCanDeferAutomaticScroll(t *testing.T) {
	skipIfNoBrowser(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body style="height:4000px"><button>Action</button></body></html>`)
	}))
	defer server.Close()

	launcher, err := NewLauncher(LauncherOptions{
		MaxBrowsers:      1,
		PageLoadStrategy: "adaptive",
		DOMWaitTime:      1,
		AutomaticScroll:  true,
		ScrollStep:       700,
		ScrollDelay:      1,
		MaxScrollSteps:   2,
		NoSandbox:        true,
	})
	require.NoError(t, err)
	defer launcher.Close()

	page, err := launcher.GetPageFromPool()
	require.NoError(t, err)
	require.NoError(t, page.Navigate(server.URL))
	require.NoError(t, page.WaitPageLoadHeurisiticsWithoutScroll())
	steps, err := page.Eval(`() => Number(window.__katanaAutoScrollSteps || 0)`)
	require.NoError(t, err)
	require.Equal(t, 0, steps.Value.Int())

	require.NoError(t, page.AutomaticScroll(3*time.Second))
	steps, err = page.Eval(`() => Number(window.__katanaAutoScrollSteps || 0)`)
	require.NoError(t, err)
	require.Greater(t, steps.Value.Int(), 0)
	launcher.PutBrowserToPool(page)
}

func TestFindNavigationsCrossesShadowRootsAndSameOriginIframes(t *testing.T) {
	skipIfNoBrowser(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!doctype html><html><body>
			<div id="6a3cdb1e-55fd-4980-8dde-fa99b8cb6c93"></div>
			<iframe id="frame" srcdoc="<button id='frame-button' onclick='this.dataset.clicked=&quot;yes&quot;'>Frame action</button>"></iframe>
			<script>
				const root = document.getElementById('6a3cdb1e-55fd-4980-8dde-fa99b8cb6c93').attachShadow({mode: 'open'});
				root.innerHTML = '<button id="shadow-button" onclick="this.dataset.clicked=\'yes\'">Shadow action</button>';
			</script>
		</body></html>`)
	}))
	defer server.Close()

	launcher, err := NewLauncher(LauncherOptions{MaxBrowsers: 1, NoSandbox: true})
	require.NoError(t, err)
	defer launcher.Close()
	page, err := launcher.GetPageFromPool()
	require.NoError(t, err)
	require.NoError(t, page.Navigate(server.URL))
	require.NoError(t, page.WaitLoad())

	navigations, err := page.FindNavigations()
	require.NoError(t, err)
	found := map[string]*types.HTMLElement{}
	for _, navigation := range navigations {
		if navigation.Element != nil {
			found[navigation.Element.TextContent] = navigation.Element
		}
	}
	for _, expected := range []string{"Shadow action", "Frame action"} {
		elementData := found[expected]
		require.NotNil(t, elementData, "missing %s", expected)
		require.NotEmpty(t, elementData.DeepLocator)
		element, err := page.GetElement(elementData)
		require.NoError(t, err)
		text, err := element.Text()
		require.NoError(t, err)
		require.Equal(t, expected, text)
		currentData, err := page.GetElementData(elementData)
		require.NoError(t, err)
		require.Equal(t, expected, currentData.TextContent)
		require.NoError(t, element.Click(proto.InputMouseButtonLeft, 1))
		clicked, err := element.Attribute("data-clicked")
		require.NoError(t, err)
		require.NotNil(t, clicked)
		require.Equal(t, "yes", *clicked)
	}
	require.Equal(t, "shadow", found["Shadow action"].DeepLocator[0].Type)
	require.Contains(t, found["Shadow action"].DeepLocator[0].Selector, `#\36 a3cdb1e`)
	require.Equal(t, "iframe", found["Frame action"].DeepLocator[0].Type)
	launcher.PutBrowserToPool(page)
}

func TestAdaptiveDOMSignatureIgnoresBackgroundResourceCount(t *testing.T) {
	first := adaptivePageMetrics{
		DOMNodes:            100,
		BodyElements:        40,
		InteractiveElements: 5,
		TextLength:          200,
		HTMLLength:          5000,
		ScrollHeight:        1200,
		ResourceCount:       10,
	}
	second := first
	second.ResourceCount = 10000
	require.Equal(t, first.signature(), second.signature())
}

func TestActionActivityWaitReturnsAtNoSignalDeadline(t *testing.T) {
	skipIfNoBrowser(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body><button id="noop">No-op</button></body></html>`)
	}))
	defer server.Close()

	launcher, err := NewLauncher(LauncherOptions{MaxBrowsers: 1, NoSandbox: true})
	require.NoError(t, err)
	defer launcher.Close()
	page, err := launcher.GetPageFromPool()
	require.NoError(t, err)
	require.NoError(t, page.Navigate(server.URL))
	require.NoError(t, page.WaitLoad())

	baseline, err := page.CaptureActionActivity()
	require.NoError(t, err)
	_, err = page.Eval(`() => document.querySelector('#noop').click()`)
	require.NoError(t, err)
	result, err := page.WaitForActionActivity(
		baseline,
		300*time.Millisecond,
		100*time.Millisecond,
		time.Second,
	)
	require.NoError(t, err)
	require.False(t, result.SignalObserved)
	require.Equal(t, "no-signal", result.Reason)
	require.GreaterOrEqual(t, result.Elapsed, 250*time.Millisecond)
	require.Less(t, result.Elapsed, 800*time.Millisecond)
	launcher.PutBrowserToPool(page)
}

func TestActionActivityWaitObservesDelayedMutation(t *testing.T) {
	skipIfNoBrowser(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body>
			<button id="delayed" onclick="setTimeout(() => { document.querySelector('#result').textContent = 'ready'; }, 250)">Delayed</button>
			<div id="result"></div>
		</body></html>`)
	}))
	defer server.Close()

	launcher, err := NewLauncher(LauncherOptions{MaxBrowsers: 1, NoSandbox: true})
	require.NoError(t, err)
	defer launcher.Close()
	page, err := launcher.GetPageFromPool()
	require.NoError(t, err)
	require.NoError(t, page.Navigate(server.URL))
	require.NoError(t, page.WaitLoad())

	baseline, err := page.CaptureActionActivity()
	require.NoError(t, err)
	_, err = page.Eval(`() => document.querySelector('#delayed').click()`)
	require.NoError(t, err)
	result, err := page.WaitForActionActivity(
		baseline,
		600*time.Millisecond,
		150*time.Millisecond,
		2*time.Second,
	)
	require.NoError(t, err)
	require.True(t, result.SignalObserved)
	require.Equal(t, "quiet", result.Reason)
	require.GreaterOrEqual(t, result.Elapsed, 300*time.Millisecond)
	require.Less(t, result.Elapsed, 1500*time.Millisecond)
	value, err := page.Eval(`() => document.querySelector('#result').textContent`)
	require.NoError(t, err)
	require.Equal(t, "ready", value.Value.Str())
	launcher.PutBrowserToPool(page)
}

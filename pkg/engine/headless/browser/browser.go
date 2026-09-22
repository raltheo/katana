package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	rodutils "github.com/go-rod/rod/lib/utils"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/katana/pkg/engine/headless/browser/cookie"
	"github.com/projectdiscovery/katana/pkg/engine/headless/browser/stealth"
	"github.com/projectdiscovery/katana/pkg/engine/headless/js"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/utils"
	"github.com/projectdiscovery/utils/chromeshell"
	"github.com/rs/xid"
)

// Launcher is a high level controller to launch browsers
// and do the execution on them.
type Launcher struct {
	browserPool rod.Pool[BrowserPage]

	opts LauncherOptions
}

// LauncherOptions contains options for the launcher
type LauncherOptions struct {
	ChromiumPath        string
	MaxBrowsers         int
	PageMaxTimeout      time.Duration
	ShowBrowser         bool
	NoSandbox           bool
	NoIncognito         bool
	Proxy               string
	SlowMotion          bool
	Trace               bool
	CookieConsentBypass bool
	AutomaticScroll     bool
	ScrollStep          int
	ScrollDelay         int
	MaxScrollSteps      int
	PageLoadStrategy    string
	ChromeWSUrl         string            // WebSocket URL to connect to existing Chrome
	DOMWaitTime         int               // Time in seconds to wait for DOM (used with domcontentloaded strategy)
	UserDataDir         string            // User-provided chrome data directory to preserve sessions
	ChromeUser          *user.User        // optional chrome user to use
	UserArguments       map[string]string // user-supplied Chrome flags via -headless-options

	ScopeValidator  ScopeValidator
	RequestCallback func(*output.Result)
}

type ScopeValidator func(string) bool

// NewLauncher returns a new launcher instance
func NewLauncher(opts LauncherOptions) (*Launcher, error) {
	// Default to "heuristic" if not specified
	if opts.PageLoadStrategy == "" {
		opts.PageLoadStrategy = "heuristic"
	}

	if opts.DOMWaitTime <= 0 {
		opts.DOMWaitTime = 5
	}
	if opts.ScrollStep <= 0 {
		opts.ScrollStep = 700
	}
	if opts.ScrollDelay < 0 {
		opts.ScrollDelay = 120
	}
	if opts.MaxScrollSteps <= 0 {
		opts.MaxScrollSteps = 40
	}

	l := &Launcher{
		opts:        opts,
		browserPool: rod.NewPool[BrowserPage](opts.MaxBrowsers),
	}

	return l, nil
}

func (l *Launcher) ScopeValidator() ScopeValidator {
	return l.opts.ScopeValidator
}

func (l *Launcher) shouldUseIncognito() bool {
	return !l.opts.NoIncognito
}

func (l *Launcher) shouldSkipHeadlessFlag(flagName string) bool {
	if l.opts.UserDataDir == "" || !l.opts.NoIncognito {
		return false
	}

	switch flagName {
	case "use-mock-keychain", "password-store", "disable-extensions", "enable-automation":
		return true
	default:
		return false
	}
}

func (l *Launcher) shouldPreserveUserDataDir(tempDir string) bool {
	return tempDir != "" && tempDir == l.opts.UserDataDir
}

func (l *Launcher) launchBrowserWithDataDir(userDataDir string) (*rod.Browser, error) {
	var launcherURL string

	// If ChromeWSUrl is provided, connect to existing Chrome instead of launching new one
	if l.opts.ChromeWSUrl != "" {
		launcherURL = l.opts.ChromeWSUrl
	} else {
		// Launch a new Chrome instance
		chromeLauncher := launcher.New().
			Leakless(true).
			Set("disable-gpu", "true").
			Set("ignore-certificate-errors", "true").
			Set("disable-crash-reporter", "true").
			Set("disable-notifications", "true").
			Set("hide-scrollbars", "true").
			Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
			Set("mute-audio", "true").
			Delete("use-mock-keychain").
			Delete("disable-ipc-flooding-protection").
			Headless(true)

		if l.shouldUseIncognito() {
			chromeLauncher = chromeLauncher.Set("incognito", "true")
		}

		for _, flag := range headlessFlags {
			splitted := strings.TrimPrefix(flag, "--")
			values := strings.Split(splitted, "=")
			flagName := values[0]
			if l.shouldSkipHeadlessFlag(flagName) {
				continue
			}
			if len(values) == 2 {
				chromeLauncher = chromeLauncher.Set(flags.Flag(values[0]), strings.Split(values[1], ",")...)
			} else {
				chromeLauncher = chromeLauncher.Set(flags.Flag(splitted), "true")
			}
		}

		if l.opts.Proxy != "" {
			chromeLauncher = chromeLauncher.Proxy(l.opts.Proxy)
			// Chrome bypasses the proxy for localhost/127.0.0.0/8/[::1]/link-local
			// unless that implicit rule is subtracted. Same token as hybrid.
			chromeLauncher = chromeLauncher.Set("proxy-bypass-list", "<-loopback>")
		}

		if l.opts.NoSandbox {
			chromeLauncher = chromeLauncher.NoSandbox(true)
		}

		if l.opts.ShowBrowser {
			chromeLauncher = chromeLauncher.Headless(false)
		}

		if l.opts.ChromiumPath != "" {
			chromeLauncher = chromeLauncher.Bin(l.opts.ChromiumPath)
		} else if !l.opts.ShowBrowser && chromeshell.Supported() {
			// Prefer chrome-headless-shell on linux/amd64 for headless crawls;
			// skip when headed since the shell binary cannot show a UI.
			if shellPath, err := chromeshell.Ensure(); err == nil {
				chromeLauncher = chromeLauncher.Bin(shellPath)
			}
		}

		if userDataDir != "" {
			chromeLauncher = chromeLauncher.UserDataDir(userDataDir)
		}

		for k, v := range l.opts.UserArguments {
			chromeLauncher = chromeLauncher.Set(flags.Flag(k), v)
		}

		var err error
		launcherURL, err = chromeLauncher.Launch()
		if err != nil {
			return nil, err
		}
	}

	browser := rod.New().
		ControlURL(launcherURL)
	if l.opts.Trace {
		browser = browser.Trace(true)
	}

	if l.opts.SlowMotion {
		browser = browser.SlowMotion(1 * time.Second)
	}
	if browserErr := browser.Connect(); browserErr != nil {
		return nil, browserErr
	}

	return browser, nil
}

// Close closes the launcher
func (l *Launcher) Close() {
	l.browserPool.Cleanup(func(b *BrowserPage) {
		b.CloseBrowserPage()
	})
	close(l.browserPool)
}

// BrowserPage is a combination of a browser and a page
type BrowserPage struct {
	*rod.Page
	Browser     *rod.Browser
	cancel      context.CancelFunc
	userDataDir string

	launcher *Launcher
}

// WaitOptions controls how WaitPageLoadHeurisitics determines navigation completion.
// All durations are conservative defaults and can be tuned later via package-level variables
// or future setter methods (kept simple here to avoid breaking public API).
type WaitOptions struct {
	URLPollInterval time.Duration // interval between successive URL polls
	URLPollTimeout  time.Duration // how long to keep polling before giving up on URL change
	PostChangeWait  time.Duration // small grace period after URL change for late requests
	IdleWait        time.Duration // network-idle window when no URL change happened
	DOMStableWait   time.Duration // DOM-stable window (used after idle)
	MaxTimeout      time.Duration // absolute upper bound for all waiting
}

// defaultWaitOptions are derived from empirical measurements on modern SPA pages.
var defaultWaitOptions = WaitOptions{
	URLPollInterval: 100 * time.Millisecond,
	URLPollTimeout:  2 * time.Second,
	PostChangeWait:  300 * time.Millisecond,
	IdleWait:        1 * time.Second,
	DOMStableWait:   1 * time.Second,
	MaxTimeout:      15 * time.Second,
}

const adaptivePageMetricsExpression = `() => {
	const now = performance.now();
	if (!window.__katanaAdaptiveWait) {
		const state = {lastMutation: now, mutationCount: 0, observed: new WeakSet()};
		window.__katanaAdaptiveWait = state;
	}
	const state = window.__katanaAdaptiveWait;
	if (!Number.isFinite(state.mutationCount)) state.mutationCount = 0;
	const roots = [];
	const documents = [];
	const seen = new Set();
	const visit = (root) => {
		if (!root || seen.has(root) || !root.querySelectorAll) return;
		seen.add(root);
		roots.push(root);
		if (root.nodeType === Node.DOCUMENT_NODE) documents.push(root);
		for (const element of root.querySelectorAll('*')) {
			if (element.shadowRoot) visit(element.shadowRoot);
			if (element.tagName === 'IFRAME') {
				try { if (element.contentDocument) visit(element.contentDocument); } catch (_) {}
			}
		}
	};
	visit(document);
	for (const root of roots) {
		const observedRoot = root.nodeType === Node.DOCUMENT_NODE ? root.documentElement : root;
		if (!observedRoot || state.observed.has(observedRoot)) continue;
		const observer = new MutationObserver((records) => {
			state.lastMutation = performance.now();
			state.mutationCount += records.length || 1;
		});
		try {
			observer.observe(observedRoot, {
				attributes: true,
				childList: true,
				characterData: true,
				subtree: true
			});
			state.observed.add(observedRoot);
		} catch (_) {}
	}
	const body = document.body;
	const root = document.documentElement;
	const selector = [
		'a[href]', 'button', 'input:not([type="hidden"])', 'select', 'textarea',
		'[role="button"]', '[role="link"]', '[onclick]', '[tabindex]:not([tabindex="-1"])'
	].join(',');
	let interactive = 0;
	let domNodes = 0;
	let bodyElements = 0;
	let textLength = 0;
	let htmlLength = 0;
	let scrollHeight = 0;
	for (const deepRoot of roots) {
		let elements = [];
		try { elements = Array.from(deepRoot.querySelectorAll('*')); } catch (_) {}
		domNodes += elements.length;
		const contentElements = deepRoot.nodeType === Node.DOCUMENT_NODE
			? Array.from(deepRoot.body?.querySelectorAll('*') || [])
			: elements;
		bodyElements += contentElements.filter((element) => ![
			'SCRIPT', 'STYLE', 'LINK', 'META', 'TEMPLATE', 'NOSCRIPT'
		].includes(element.tagName)).length;
		for (const element of elements) {
			if (!element.matches?.(selector)) continue;
			const view = element.ownerDocument?.defaultView || window;
			const style = view.getComputedStyle(element);
			const rect = element.getBoundingClientRect();
			if (style.display !== 'none' && style.visibility !== 'hidden' &&
				Number(style.opacity || 1) !== 0 && rect.width > 0 && rect.height > 0) interactive++;
		}
		if (deepRoot.nodeType === Node.DOCUMENT_NODE) {
			const deepBody = deepRoot.body;
			const deepDocument = deepRoot.documentElement;
			textLength += String(deepBody?.innerText || '').trim().length;
			htmlLength += String(deepDocument?.outerHTML || '').length;
			scrollHeight = Math.max(scrollHeight, deepDocument?.scrollHeight || 0, deepBody?.scrollHeight || 0);
		} else {
			textLength += String(deepRoot.textContent || '').trim().length;
			htmlLength += String(deepRoot.innerHTML || '').length;
			scrollHeight = Math.max(scrollHeight, deepRoot.scrollHeight || 0);
		}
	}
	let lastResource = 0;
	let resources = 0;
	for (const deepDocument of documents) {
		try {
			const deepPerformance = deepDocument.defaultView.performance;
			for (const entry of deepPerformance.getEntriesByType('resource')) {
				resources += 1;
				if (deepDocument === document) lastResource = Math.max(lastResource, entry.responseEnd || entry.startTime || 0);
			}
		} catch (_) {}
	}
	return {
		url: String(window.location.href || ''),
		ready_state: String(document.readyState || ''),
		dom_nodes: domNodes,
		body_elements: bodyElements,
		interactive_elements: interactive,
		text_length: textLength,
		html_length: htmlLength,
		scroll_height: scrollHeight,
		resource_count: resources,
		mutation_count: Number(window.__katanaAdaptiveWait.mutationCount || 0),
		mutation_age_ms: Math.max(0, now - window.__katanaAdaptiveWait.lastMutation),
		resource_age_ms: lastResource > 0 ? Math.max(0, now - lastResource) : now,
		scroll_steps: Number(window.__katanaAutoScrollSteps || 0)
	};
}`

type adaptivePageMetrics struct {
	URL                 string  `json:"url"`
	ReadyState          string  `json:"ready_state"`
	DOMNodes            int     `json:"dom_nodes"`
	BodyElements        int     `json:"body_elements"`
	InteractiveElements int     `json:"interactive_elements"`
	TextLength          int     `json:"text_length"`
	HTMLLength          int     `json:"html_length"`
	ScrollHeight        int     `json:"scroll_height"`
	ResourceCount       int     `json:"resource_count"`
	MutationCount       int64   `json:"mutation_count"`
	MutationAgeMS       float64 `json:"mutation_age_ms"`
	ResourceAgeMS       float64 `json:"resource_age_ms"`
	ScrollSteps         int     `json:"scroll_steps"`
}

func (m adaptivePageMetrics) meaningful() bool {
	ready := m.ReadyState == "interactive" || m.ReadyState == "complete"
	content := m.TextLength > 0 || m.InteractiveElements > 0 || m.BodyElements >= 2
	return ready && m.BodyElements > 0 && m.HTMLLength >= 512 && content
}

func (m adaptivePageMetrics) signature() string {
	return fmt.Sprintf(
		"%d:%d:%d:%d:%d:%d",
		m.DOMNodes,
		m.BodyElements,
		m.InteractiveElements,
		m.TextLength,
		m.HTMLLength,
		m.ScrollHeight,
	)
}

func (b *BrowserPage) adaptivePageMetrics() (adaptivePageMetrics, error) {
	value, err := b.Eval(adaptivePageMetricsExpression)
	if err != nil {
		return adaptivePageMetrics{}, err
	}
	metrics := adaptivePageMetrics{}
	if err := value.Value.Unmarshal(&metrics); err != nil {
		return adaptivePageMetrics{}, err
	}
	return metrics, nil
}

// ActionActivitySnapshot is a cheap baseline captured immediately before a
// physical click. MutationCount is maintained by the observer installed by
// adaptivePageMetrics, so synchronous DOM changes cannot be missed between the
// mouse event and the first post-click poll.
type ActionActivitySnapshot struct {
	URL           string
	DOMSignature  string
	ResourceCount int
	MutationCount int64
}

// ActionActivityResult explains why the bounded post-click wait completed.
// It is intentionally small so callers can journal timing decisions without
// coupling themselves to the full adaptive DOM metrics structure.
type ActionActivityResult struct {
	SignalObserved bool
	Reason         string
	Elapsed        time.Duration
}

func (b *BrowserPage) CaptureActionActivity() (ActionActivitySnapshot, error) {
	metrics, err := b.adaptivePageMetrics()
	if err != nil {
		return ActionActivitySnapshot{}, err
	}
	return ActionActivitySnapshot{
		URL:           metrics.URL,
		DOMSignature:  metrics.signature(),
		ResourceCount: metrics.ResourceCount,
		MutationCount: metrics.MutationCount,
	}, nil
}

func sleepWithPageContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// WaitForActionActivity waits briefly for the first observable effect of a
// click, then only as long as the page keeps making meaningful progress. A
// true no-op returns after signalTimeout. A changing page receives the full
// maxTimeout budget, while a stable DOM is accepted after a conservative
// fallback window even when analytics traffic never becomes quiet.
func (b *BrowserPage) WaitForActionActivity(
	baseline ActionActivitySnapshot,
	signalTimeout time.Duration,
	quietPeriod time.Duration,
	maxTimeout time.Duration,
) (ActionActivityResult, error) {
	started := time.Now()
	result := ActionActivityResult{}
	if signalTimeout <= 0 {
		result.Reason = "disabled"
		return result, nil
	}
	if quietPeriod <= 0 {
		quietPeriod = 750 * time.Millisecond
	}
	if maxTimeout < signalTimeout+quietPeriod {
		maxTimeout = signalTimeout + quietPeriod
	}

	const pollInterval = 100 * time.Millisecond
	const stableDOMFallback = 4 * time.Second
	ctx := b.Page.GetContext()
	deadline := started.Add(maxTimeout)
	signalDeadline := started.Add(signalTimeout)
	lastURL := baseline.URL
	lastSignature := baseline.DOMSignature
	lastResourceCount := baseline.ResourceCount
	lastMutationCount := baseline.MutationCount
	lastProgress := started
	lastVisualProgress := started

	finish := func(reason string) (ActionActivityResult, error) {
		result.Reason = reason
		result.Elapsed = time.Since(started)
		return result, nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		now := time.Now()
		if !now.Before(deadline) {
			return finish("progress-timeout")
		}

		metrics, err := b.adaptivePageMetrics()
		if err != nil {
			// A document swap can make Runtime.evaluate briefly unavailable. Treat
			// that as activity so a real navigation retains the full progress budget.
			if !result.SignalObserved {
				result.SignalObserved = true
				lastProgress = now
				lastVisualProgress = now
			}
			if err := sleepWithPageContext(ctx, pollInterval); err != nil {
				return result, err
			}
			continue
		}

		urlChanged := metrics.URL != lastURL
		domChanged := metrics.signature() != lastSignature
		resourceChanged := metrics.ResourceCount != lastResourceCount
		mutationChanged := metrics.MutationCount != lastMutationCount
		if urlChanged || domChanged || resourceChanged || mutationChanged {
			result.SignalObserved = true
			lastProgress = now
		}
		if urlChanged || domChanged {
			lastVisualProgress = now
		}
		lastURL = metrics.URL
		lastSignature = metrics.signature()
		lastResourceCount = metrics.ResourceCount
		lastMutationCount = metrics.MutationCount

		if !result.SignalObserved {
			if !now.Before(signalDeadline) {
				return finish("no-signal")
			}
		} else {
			quiet := now.Sub(lastProgress) >= quietPeriod &&
				metrics.MutationAgeMS >= float64(quietPeriod.Milliseconds()) &&
				metrics.ResourceAgeMS >= float64(quietPeriod.Milliseconds())
			if quiet {
				return finish("quiet")
			}
			// Dynamic clocks and telemetry can keep counters moving without
			// changing the rendered state. Retain the existing conservative
			// four-second fallback instead of waiting for the full SPA timeout.
			if now.Sub(lastVisualProgress) >= stableDOMFallback {
				return finish("stable-dom")
			}
		}

		if err := sleepWithPageContext(ctx, pollInterval); err != nil {
			return result, err
		}
	}
}

func (b *BrowserPage) automaticScroll(timeout time.Duration) error {
	if !b.launcher.opts.AutomaticScroll {
		return nil
	}
	script := fmt.Sprintf(`async () => {
		const step = %d;
		const delay = %d;
		const limit = %d;
		const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
		const sleepReal = window.__katanaSleep || sleep;
		// requestAnimationFrame may be suspended indefinitely in a background
		// external-Chrome tab. Race it with a real timer so automatic scrolling
		// remains bounded without skipping normal paint synchronization.
		const painted = () => new Promise(resolve => {
			let settled = false;
			const finish = () => {
				if (settled) return;
				settled = true;
				resolve();
			};
			requestAnimationFrame(finish);
			sleepReal(100).then(finish);
		});
		const contexts = [];
		const seenRoots = new Set();
		const visit = (root) => {
			if (!root || seenRoots.has(root) || !root.querySelectorAll) return;
			seenRoots.add(root);
			if (root.nodeType === Node.DOCUMENT_NODE && root.defaultView) {
				contexts.push({kind: 'window', target: root.defaultView, start: root.defaultView.scrollY || 0});
			}
			for (const element of root.querySelectorAll('*')) {
				if (element.shadowRoot) visit(element.shadowRoot);
				if (element.tagName === 'IFRAME') {
					try { if (element.contentDocument) visit(element.contentDocument); } catch (_) {}
				}
				try {
					const view = element.ownerDocument?.defaultView || window;
					const style = view.getComputedStyle(element);
					if (/(auto|scroll|overlay)/.test(style.overflowY) ||
						/(auto|scroll|overlay)/.test(element.style?.overflowY || '')) {
						contexts.push({kind: 'element', target: element, start: element.scrollTop || 0});
					}
				} catch (_) {}
			}
		};
		visit(document);
		let steps = 0;
		for (const context of contexts) {
			if (context.kind === 'window') {
				const doc = context.target.document;
				const initialHeight = Math.max(doc?.documentElement?.scrollHeight || 0, doc?.body?.scrollHeight || 0);
				if (doc?.body && initialHeight <= context.target.innerHeight + 2) {
					const probeHeight = Math.max(step + context.target.innerHeight, context.target.innerHeight * 2) + 'px';
					context.originalBodyMinHeight = doc.body.style.minHeight;
					context.originalRootMinHeight = doc.documentElement.style.minHeight;
					doc.body.style.minHeight = probeHeight;
					doc.documentElement.style.minHeight = probeHeight;
					void doc.body.getBoundingClientRect();
					context.probed = true;
				}
			} else if (context.target.scrollHeight <= context.target.clientHeight + 2) {
				const spacer = context.target.ownerDocument.createElement('div');
				spacer.setAttribute('data-katana-scroll-probe', '');
				spacer.style.cssText = 'height:' + Math.max(step + context.target.clientHeight, context.target.clientHeight * 2) + 'px;pointer-events:none;';
				context.target.appendChild(spacer);
				context.spacer = spacer;
			}
			context.previousHeight = -1;
			context.done = false;
		}
		while (steps < limit) {
			let progressed = false;
			for (const context of contexts) {
				if (context.done) continue;
				const target = context.target;
				const doc = context.kind === 'window' ? target.document : null;
				const height = context.kind === 'window'
					? Math.max(doc?.documentElement?.scrollHeight || 0, doc?.body?.scrollHeight || 0)
					: target.scrollHeight;
				const current = context.kind === 'window' ? (target.scrollY || 0) : target.scrollTop;
				const viewport = context.kind === 'window' ? target.innerHeight : target.clientHeight;
				if (current + viewport >= height - 2 && height === context.previousHeight) {
					context.done = true;
					continue;
				}
				context.previousHeight = height;
				if (context.kind === 'window') {
					target.scrollTo(0, Math.min(current + step, height));
					target.dispatchEvent(new target.Event('scroll'));
				} else {
					target.scrollTop = Math.min(current + step, height);
					const view = target.ownerDocument?.defaultView || window;
					target.dispatchEvent(new view.Event('scroll', {bubbles: true}));
				}
				steps += 1;
				progressed = true;
				await painted();
				await sleep(delay);
				if (steps >= limit) break;
			}
			if (!progressed) break;
		}
		// Let async lazy-load handlers consume their responses before restoring
		// the original scroll position. Timers are accelerated by Katana, while
		// animation frames remain tied to real browser paints.
		for (let frame = 0; frame < 12; frame++) await painted();
		await sleepReal(500);
		for (const context of contexts.reverse()) {
			if (context.kind === 'window') context.target.scrollTo(0, context.start);
			else context.target.scrollTop = context.start;
			if (context.probed) {
				context.target.document.body.style.minHeight = context.originalBodyMinHeight;
				context.target.document.documentElement.style.minHeight = context.originalRootMinHeight;
			}
			if (context.spacer) context.spacer.remove();
		}
		await sleep(delay);
		window.__katanaAutoScrollSteps = steps;
		return steps;
	}`, b.launcher.opts.ScrollStep, b.launcher.opts.ScrollDelay, b.launcher.opts.MaxScrollSteps)
	page := b.Page
	if timeout > 0 {
		page = b.Timeout(timeout)
	}
	_, err := page.Eval(script)
	return err
}

// waitAdaptive waits for a meaningful rendered DOM rather than treating the
// first quiet network gap as completion. DOMWaitTime is an upper bound: fast
// pages finish as soon as DOM mutations and resource loads have both remained
// quiet for a short window. A stable rendered DOM is also accepted after a
// bounded delay when background telemetry never becomes idle. Optional
// scrolling happens before readiness so lazy-loaded content is discovered.
func (b *BrowserPage) waitAdaptive(allowScroll bool) error {
	maximum := time.Duration(b.launcher.opts.DOMWaitTime) * time.Second
	if maximum <= 0 {
		maximum = 5 * time.Second
	}
	started := time.Now()
	deadline := started.Add(maximum)
	loadPage := b.Timeout(maximum)
	_ = loadPage.WaitLoad()

	const pollInterval = 100 * time.Millisecond
	const quietWindow = 2 * time.Second
	var meaningfulSince time.Time
	var stableSince time.Time
	lastSignature := ""
	scrolled := false

	for time.Now().Before(deadline) {
		metrics, err := b.adaptivePageMetrics()
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		now := time.Now()
		signature := metrics.signature()
		if signature != lastSignature {
			lastSignature = signature
			stableSince = now
		}
		if !metrics.meaningful() {
			meaningfulSince = time.Time{}
			time.Sleep(pollInterval)
			continue
		}
		if meaningfulSince.IsZero() {
			meaningfulSince = now
		}

		if allowScroll && b.launcher.opts.AutomaticScroll && !scrolled {
			if err := b.automaticScroll(time.Until(deadline)); err == nil {
				scrolled = true
				meaningfulSince = time.Now()
				stableSince = meaningfulSince
				lastSignature = ""
				continue
			}
			// A scroll failure must not prevent the bounded readiness check.
			scrolled = true
		}

		quiet := now.Sub(stableSince) >= quietWindow &&
			metrics.MutationAgeMS >= float64(quietWindow.Milliseconds()) &&
			metrics.ResourceAgeMS >= float64(quietWindow.Milliseconds())
		// Telemetry, long polling and WebSockets must not keep a rendered SPA
		// blocked forever. A stable meaningful DOM is sufficient even while new
		// resource entries continue to appear.
		meaningfulFallback := now.Sub(meaningfulSince) >= 4*time.Second &&
			now.Sub(stableSince) >= quietWindow
		if quiet || meaningfulFallback {
			return nil
		}
		time.Sleep(pollInterval)
	}

	// The strategy is deliberately bounded. The caller can still inspect the
	// current page and decide, using stronger evidence, whether it was rendered.
	return nil
}

// WaitPageLoadHeurisitics waits for the page to load using multiple heuristics.
// Strategy order:
//  1. Wait for initial load event (covers classic navigation & first paint).
//  2. Poll for a URL change – the strongest signal on SPAs with client-side routing.
//  3. If URL changes, wait a short grace period + network-idle window.
//  4. If URL doesn't change, fall back to network-idle + DOM-stable windows.
//
// This keeps fast pages fast while still succeeding on noisy, long-running SPAs.
func (b *BrowserPage) WaitPageLoadHeurisitics() error {
	return b.waitPageLoadHeuristics(true)
}

// WaitPageLoadHeurisiticsWithoutScroll waits for readiness without performing
// the expensive whole-page lazy-load pass. The crawler uses it immediately
// after an action, then scrolls once only when the rendered state is new.
func (b *BrowserPage) WaitPageLoadHeurisiticsWithoutScroll() error {
	return b.waitPageLoadHeuristics(false)
}

func (b *BrowserPage) waitPageLoadHeuristics(allowScroll bool) error {
	// Respect the page load strategy from launcher options
	strategy := b.launcher.opts.PageLoadStrategy

	switch strategy {
	case "none":
		// Don't wait at all, return immediately
		return nil

	case "load":
		// Just wait for the load event
		chained := b.Timeout(15 * time.Second)
		return chained.WaitLoad()

	case "domcontentloaded":
		// WaitLoad checks document.readyState via JS, so it's safe to call
		// after Navigate() has already started (no race with missed events).
		chained := b.Timeout(15 * time.Second)
		_ = chained.WaitLoad()
		if b.launcher.opts.DOMWaitTime > 0 {
			time.Sleep(time.Duration(b.launcher.opts.DOMWaitTime) * time.Second)
		}
		return nil

	case "networkidle":
		// Wait for network activity to stop
		chained := b.Timeout(15 * time.Second)
		_ = chained.WaitLoad()
		_ = chained.WaitIdle(2 * time.Second)
		return nil

	case "adaptive":
		return b.waitAdaptive(allowScroll)

	case "heuristic":
		fallthrough
	default:
		// Use the original heuristic approach
		opts := defaultWaitOptions

		chained := b.Timeout(opts.MaxTimeout)

		// 1. Wait for the basic load event (DOMContentLoaded / load).
		_ = chained.WaitLoad()

		// 2. Capture the current URL so we can detect route changes.
		urlVal, _ := b.Eval("() => window.location.href")
		startURL := ""
		if urlVal != nil {
			startURL = urlVal.Value.Str()
		}

		// 3. Poll for a different URL for up to URLPollTimeout.
		urlChanged := false
		if startURL != "" {
			pollCount := int(opts.URLPollTimeout / opts.URLPollInterval)
			for i := 0; i < pollCount; i++ {
				time.Sleep(opts.URLPollInterval)
				cur, err := b.Eval("() => window.location.href")
				if err == nil && cur != nil && cur.Value.Str() != startURL {
					urlChanged = true
					break
				}
			}
		}

		if urlChanged {
			// 4a. URL changed – short grace period then network idle & done.
			_ = chained.WaitIdle(opts.PostChangeWait)
			return nil
		}

		// 4b. URL didn't change – fall back to broader heuristics.
		_ = chained.WaitIdle(opts.IdleWait)
		_ = b.WaitNewStable(opts.DOMStableWait)

		return nil
	}
}

// AutomaticScroll materializes lazy content using Katana's configured bounded
// scroll policy. It is intentionally explicit so the crawler can run it once
// per genuinely new post-action state.
func (b *BrowserPage) AutomaticScroll(timeout time.Duration) error {
	if !b.launcher.opts.AutomaticScroll {
		return nil
	}
	return b.automaticScroll(timeout)
}

// WaitPageLoadHeuristicsFallback provides the enhanced timeouts for complex navigation
func (b *BrowserPage) WaitPageLoadHeuristicsFallback() error {
	chainedTimeout := b.Timeout(20 * time.Second)

	_ = chainedTimeout.WaitLoad()
	_ = chainedTimeout.WaitIdle(4 * time.Second)
	_ = b.WaitNewStable(2 * time.Second)

	return nil
}

// WaitStable waits until the page is stable for d duration.
func (p *BrowserPage) WaitNewStable(d time.Duration) error {
	// Enforce an upper-bound on how long we will wait for the page to become
	// stable. We simply reuse the heuristic window (d) and give the combined
	// operation 2× that duration. This guarantees that callers will be
	// released after a finite time instead of blocking forever when a page
	// keeps a long-lived connection open (analytics beacons, WebSockets, etc.).

	chained := p.Timeout(2 * d)

	var err error
	setErr := sync.Once{}

	rodutils.All(func() {
		e := chained.WaitLoad()
		setErr.Do(func() { err = e })
	}, func() {
		chained.WaitRequestIdle(d, nil, []string{}, nil)()
	}, func() {
		e := chained.WaitDOMStable(d, 0)
		setErr.Do(func() { err = e })
	})()

	return err
}

func (l *Launcher) createBrowserPageFunc() (*BrowserPage, error) {
	// When using ChromeWSUrl, we don't need temp directories
	// since we're connecting to an existing browser
	var tempDir string
	shouldCleanupTempDir := false

	if l.opts.ChromeWSUrl == "" {
		if l.opts.UserDataDir != "" {
			// Use user-provided data directory (preserve sessions/cookies)
			tempDir = l.opts.UserDataDir
			shouldCleanupTempDir = false
		} else if l.opts.ChromeUser != nil {
			var err error
			tempDir, err = os.MkdirTemp(l.opts.ChromeUser.HomeDir, "chrome-data-*")
			if err != nil {
				return nil, errors.Wrap(err, "could not create temporary chrome data directory")
			}

			uid, err := strconv.Atoi(l.opts.ChromeUser.Uid)
			if err != nil {
				_ = os.RemoveAll(tempDir)
				return nil, errors.Wrap(err, "invalid user ID")
			}
			gid, err := strconv.Atoi(l.opts.ChromeUser.Gid)
			if err != nil {
				_ = os.RemoveAll(tempDir)
				return nil, errors.Wrap(err, "invalid group ID")
			}
			if err := os.Chown(tempDir, uid, gid); err != nil {
				_ = os.RemoveAll(tempDir)
				return nil, errors.Wrap(err, "could not change ownership of chrome data directory")
			}
			shouldCleanupTempDir = true
		} else {
			var err error
			tempDir, err = os.MkdirTemp("", "katana-chrome-data-*")
			if err != nil {
				return nil, errors.Wrap(err, "could not create temporary chrome data directory")
			}
			shouldCleanupTempDir = true
		}
	}

	browser, err := l.launchBrowserWithDataDir(tempDir)
	if err != nil {
		if shouldCleanupTempDir {
			_ = os.RemoveAll(tempDir)
		}
		return nil, err
	}

	page, err := browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, errors.Wrap(err, "could not create new page")
	}

	successfulPageCreation := false
	defer func() {
		if !successfulPageCreation {
			_ = page.Close()
			if l.opts.ChromeWSUrl == "" {
				_ = browser.Close()
			}
			if shouldCleanupTempDir {
				_ = os.RemoveAll(tempDir)
			}
		}
	}()

	page = page.Sleeper(func() rodutils.Sleeper {
		return backoffCountSleeper(100*time.Millisecond, 1*time.Second, 3, func(d time.Duration) time.Duration {
			return d * 1
		})
	})
	ctx := page.GetContext()
	cancelCtx, cancel := context.WithCancel(ctx)
	page = page.Context(cancelCtx)

	browserPage := &BrowserPage{
		Page:        page,
		Browser:     browser,
		launcher:    l,
		cancel:      cancel,
		userDataDir: tempDir,
	}
	if err := browserPage.handlePageDialogBoxes(); err != nil {
		return nil, err
	}

	// Add stealth evasion JS
	_, err = page.EvalOnNewDocument(stealth.JS)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize stealth")
	}
	err = js.InitJavascriptEnv(page)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize javascript env")
	}

	// Success - cancel any deferred cleanup
	successfulPageCreation = true
	return browserPage, nil
}

// GetPageFromPool returns a page from the pool
func (l *Launcher) GetPageFromPool() (*BrowserPage, error) {
	browserPage, err := l.browserPool.Get(l.createBrowserPageFunc)
	if err != nil {
		return nil, err
	}
	// TODO: should we check if the browser is alive because sometimes it
	// might die?
	return browserPage, nil
}

// backoffCountSleeper returns a sleeper that uses backoff strategy but stops after max attempts.
// It combines the functionality of BackoffSleeper and CountSleeper.
func backoffCountSleeper(initInterval, maxInterval time.Duration, maxAttempts int, algorithm func(time.Duration) time.Duration) rodutils.Sleeper {
	backoff := rodutils.BackoffSleeper(initInterval, maxInterval, algorithm)
	count := rodutils.CountSleeper(maxAttempts)

	return rodutils.EachSleepers(backoff, count)
}

func (b *BrowserPage) handlePageDialogBoxes() error {
	err := proto.FetchEnable{
		Patterns: []*proto.FetchRequestPattern{
			{
				URLPattern:   "*",
				RequestStage: proto.FetchRequestStageResponse,
			},
		},
	}.Call(b.Page)
	if err != nil {
		return errors.Wrap(err, "could not enable fetch domain")
	}

	go b.EachEvent(
		func(e *proto.PageJavascriptDialogOpening) {
			_ = proto.PageHandleJavaScriptDialog{
				Accept:     true,
				PromptText: xid.New().String(),
			}.Call(b.Page)
		},

		func(e *proto.FetchRequestPaused) {
			if b.launcher.opts.CookieConsentBypass {
				// Check if request should be blocked by cookie consent rules
				var originStr string
				if origin, ok := e.Request.Headers["Origin"]; ok {
					originStr = origin.Str()
				}
				if cookie.ShouldBlockRequest(e.Request.URL, e.ResourceType, originStr) {
					_ = proto.FetchFailRequest{
						RequestID:   e.RequestID,
						ErrorReason: proto.NetworkErrorReasonBlockedByClient,
					}.Call(b.Page)
					return
				}
			}

			if e.ResponseStatusCode == nil || e.ResponseErrorReason != "" || (*e.ResponseStatusCode >= 301 && *e.ResponseStatusCode <= 308) {
				if err := fetchContinueRequest(b.Page, e); err != nil {
					slog.Warn("fetchContinueRequest failed", "error", err)
				}
				return
			}
			body, err := fetchGetResponseBody(b.Page, e)
			if err != nil {
				// Continue the request even if we can't get the body
				if err := fetchContinueRequest(b.Page, e); err != nil {
					slog.Warn("fetchContinueRequest failed", "error", err)
				}
				return
			}
			if err := fetchContinueRequest(b.Page, e); err != nil {
				slog.Warn("fetchContinueRequest failed", "error", err)
			}

			httpreq, err := netHTTPRequestFromProto(e.Request)
			if err != nil {
				return
			}

			rawBytesRequest, _ := httputil.DumpRequestOut(httpreq, true)

			req := navigation.Request{
				Method:  httpreq.Method,
				URL:     httpreq.URL.String(),
				Body:    e.Request.PostData,
				Headers: utils.FlattenHeaders(httpreq.Header),
				Raw:     string(rawBytesRequest),
			}

			httpresp := netHTTPResponseFromProto(e, body)
			httpresp.Request = httpreq

			rawBytesResponse, _ := httputil.DumpResponse(httpresp, true)

			doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
			if err != nil {
				slog.Warn("could not parse response body", "error", err)
			}
			resp := &navigation.Response{
				Body:          string(body),
				StatusCode:    httpresp.StatusCode,
				Headers:       utils.FlattenHeaders(httpresp.Header),
				Raw:           string(rawBytesResponse),
				ContentLength: httpresp.ContentLength,
				Resp:          httpresp,
				Reader:        doc,
			}
			if b.launcher.opts.RequestCallback != nil {
				b.launcher.opts.RequestCallback(&output.Result{
					Timestamp: time.Now(),
					Request:   &req,
					Response:  resp,
				})
			}
		},
	)()
	return nil
}

func fetchContinueRequest(page *rod.Page, e *proto.FetchRequestPaused) error {
	return proto.FetchContinueRequest{
		RequestID: e.RequestID,
	}.Call(page)
}

// fetchGetResponseBody get request body.
func fetchGetResponseBody(page *rod.Page, e *proto.FetchRequestPaused) ([]byte, error) {
	m := proto.FetchGetResponseBody{
		RequestID: e.RequestID,
	}
	r, err := m.Call(page)
	if err != nil {
		return nil, err
	}

	if !r.Base64Encoded {
		return []byte(r.Body), nil
	}

	bs, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

func netHTTPRequestFromProto(e *proto.NetworkRequest) (*http.Request, error) {
	req, err := http.NewRequest(e.Method, e.URL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create new request")
	}
	for k, v := range e.Headers {
		req.Header.Set(k, v.Str())
	}
	if e.PostData != "" {
		req.Body = io.NopCloser(strings.NewReader(e.PostData))
		req.ContentLength = int64(len(e.PostData))
	}
	return req, nil
}

func netHTTPResponseFromProto(e *proto.FetchRequestPaused, body []byte) *http.Response {
	httpresp := &http.Response{
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		StatusCode:    *e.ResponseStatusCode,
		Status:        e.ResponseStatusText,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	for _, header := range e.ResponseHeaders {
		httpresp.Header.Set(header.Name, header.Value)
	}
	return httpresp
}

func (l *Launcher) PutBrowserToPool(browser *BrowserPage) {
	// Discard pages that hit a deadline or were cancelled to avoid immediately
	// returning a poisoned page that will fail every subsequent call.
	if cerr := browser.Page.GetContext().Err(); cerr != nil {
		l.DiscardBrowserPage(browser)
		return
	}
	// If the browser is not connected, close it
	if !isBrowserConnected(browser.Browser) {
		l.DiscardBrowserPage(browser)
		return
	}

	// When attached to an externally managed Chrome via ChromeWSUrl,
	// never close other browser tabs. They belong to the caller/user,
	// not to Katana.
	if l.opts.ChromeWSUrl != "" {
		l.browserPool.Put(browser)
		return
	}

	pages, err := browser.Browser.Pages()
	if err != nil {
		l.DiscardBrowserPage(browser)
		return
	}

	currentPageID := browser.TargetID
	for _, page := range pages {
		if page.TargetID != currentPageID {
			_ = page.Close()
		}
	}
	l.browserPool.Put(browser)
}

// DiscardBrowserPage removes a poisoned page and returns an empty token to the
// bounded pool so the next action can create a clean replacement. Without the
// nil token, Pool.Get blocks forever once a timed-out page has been removed.
func (l *Launcher) DiscardBrowserPage(browser *BrowserPage) {
	if browser != nil {
		browser.CloseBrowserPage()
	}
	l.browserPool.Put(nil)
}

func isBrowserConnected(browser *rod.Browser) bool {
	getVersionResult, err := proto.BrowserGetVersion{}.Call(browser)
	if err != nil {
		return false
	}
	if getVersionResult == nil || getVersionResult.Product == "" {
		return false
	}
	return true
}

func (b *BrowserPage) CloseBrowserPage() {
	// Use the browser connection rather than the page context: the latter is
	// commonly already cancelled when this cleanup is needed. Target cleanup
	// is bounded so a renderer stuck in JavaScript cannot stall the crawler.
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelClose()
	client := b.Browser.Context(closeCtx)
	if b.TargetID != "" {
		_, _ = proto.TargetCloseTarget{TargetID: b.TargetID}.Call(client)
	}

	// Only close the browser if we launched it ourselves (not connecting via ChromeWSUrl)
	// If ChromeWSUrl was used, we should leave the browser running
	if b.launcher.opts.ChromeWSUrl == "" {
		_ = client.Close()
	}
	b.cancel()

	// Only cleanup temp data dir if we created it (not user-provided)
	if b.userDataDir != "" && !b.launcher.shouldPreserveUserDataDir(b.userDataDir) {
		_ = os.RemoveAll(b.userDataDir)
	}
}

// taken from playwright
var headlessFlags = []string{
	"--disable-field-trial-config", // https://source.chromium.org/chromium/chromium/src/+/main:testing/variations/README.md
	"--disable-background-networking",
	"--enable-features=NetworkService,NetworkServiceInProcess",
	"--disable-background-timer-throttling",
	"--disable-backgrounding-occluded-windows",
	"--disable-back-forward-cache", // Avoids surprises like main request not being intercepted during page.goBack().
	"--disable-breakpad",
	"--disable-client-side-phishing-detection",
	"--disable-component-extensions-with-background-pages",
	"--disable-component-update", // Avoids unneeded network activity after startup.
	"--no-default-browser-check",
	"--disable-default-apps",
	"--disable-dev-shm-usage",
	"--disable-extensions",
	// AvoidUnnecessaryBeforeUnloadCheckSync - https://github.com/microsoft/playwright/issues/14047
	// Translate - https://github.com/microsoft/playwright/issues/16126
	// HttpsUpgrades - https://github.com/microsoft/playwright/pull/27605
	// PaintHolding - https://github.com/microsoft/playwright/issues/28023
	"--disable-features=ImprovedCookieControls,LazyFrameLoading,GlobalMediaControls,DestroyProfileOnBrowserClose,MediaRouter,DialMediaRouteProvider,AcceptCHFrame,AutoExpandDetailsElement,CertificateTransparencyComponentUpdater,AvoidUnnecessaryBeforeUnloadCheckSync,Translate,HttpsUpgrades,PaintHolding",
	"--allow-pre-commit-input",
	"--disable-hang-monitor",
	"--disable-popup-blocking",
	"--disable-prompt-on-repost",
	"--disable-renderer-backgrounding",
	"--force-color-profile=srgb",
	"--metrics-recording-only",
	"--no-first-run",
	"--enable-automation",
	"--password-store=basic",
	"--use-mock-keychain",
	// See https://chromium-review.googlesource.com/c/chromium/src/+/2436773
	"--no-service-autorun",
	"--export-tagged-pdf",
	// https://chromium-review.googlesource.com/c/chromium/src/+/4853540
	"--disable-search-engine-choice-screen",
	// https://issues.chromium.org/41491762
	"--unsafely-disable-devtools-self-xss-warnings",
}

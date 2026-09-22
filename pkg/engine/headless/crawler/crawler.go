package crawler

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adrianbrad/queue"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/rod/lib/utils"
	"github.com/happyhackingspace/dit"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/headless/browser"
	"github.com/projectdiscovery/katana/pkg/engine/headless/captcha"
	"github.com/projectdiscovery/katana/pkg/engine/headless/crawler/diagnostics"
	"github.com/projectdiscovery/katana/pkg/engine/headless/crawler/normalizer"
	"github.com/projectdiscovery/katana/pkg/engine/headless/crawler/normalizer/simhash"
	"github.com/projectdiscovery/katana/pkg/engine/headless/graph"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/projectdiscovery/katana/pkg/output"
)

type Crawler struct {
	logger                 *slog.Logger
	launcher               *browser.Launcher
	options                Options
	crawlQueue             queue.Queue[*types.Action]
	crawlGraph             *graph.CrawlGraph
	simhashOracle          *simhash.Oracle
	uniqueActions          map[string]struct{}
	diagnostics            diagnostics.Writer
	actionJournal          *actionJournal
	actionDedupKeys        map[string]struct{}
	seedURL                string
	actionsTried           int
	actionRetries          map[string]int
	actionPreflightRetries map[string]actionPreflightRetry
	originRestoreFailures  map[string]int
	invalidOrigins         map[string]string
	targetFamilyFailures   map[string]int
	invalidTargetFamilies  map[string]string
	loggedIn               bool
}

type Options struct {
	Context                 context.Context
	ChromiumPath            string
	MaxBrowsers             int
	MaxDepth                int
	PageMaxTimeout          time.Duration
	NoSandbox               bool
	NoIncognito             bool
	ShowBrowser             bool
	SlowMotion              bool
	MaxCrawlDuration        time.Duration
	MaxFailureCount         int
	ContinueOnActionFailure bool
	MaxStaleActionFamily    int
	MaxActionDepth          int
	MaxActionsPerState      int
	MaxActionsPerCrawl      int
	MaxActionRuntime        time.Duration
	MaxActionRetries        int
	ActionPreflightTimeout  time.Duration
	ActionSignalTimeout     time.Duration
	ActionQuietPeriod       time.Duration
	CaptureNewTabs          bool
	ActionLogFile           string
	ActionDedupFile         string
	Trace                   bool
	CookieConsentBypass     bool
	AutomaticFormFill       bool
	AutomaticScroll         bool
	ScrollStep              int
	ScrollDelay             int
	MaxScrollSteps          int
	PageLoadStrategy        string
	ChromeWSUrl             string
	DOMWaitTime             int
	UserDataDir             string

	// EnableDiagnostics enables the diagnostics mode
	// which writes diagnostic information to a directory
	// specified by the DiagnosticsDir optionally.
	EnableDiagnostics bool
	DiagnosticsDir    string

	Proxy           string
	Logger          *slog.Logger
	ScopeValidator  browser.ScopeValidator
	RequestCallback func(*output.Result)
	ChromeUser      *user.User
	CaptchaHandler  *captcha.Handler
	UserArguments   map[string]string

	AuthUsername  string
	AuthPassword  string
	DitClassifier *dit.Classifier

	// Hooks installs optional lifecycle callbacks. See Hooks for semantics.
	// The zero value disables all callbacks.
	Hooks Hooks
}

var domNormalizer *normalizer.Normalizer
var initOnce sync.Once
var initError error

func init() {
	initOnce.Do(func() {
		var err error
		domNormalizer, err = normalizer.New()
		if err != nil {
			initError = errors.Wrap(err, "failed to create domnormalizer")
		}
	})
}

func New(opts Options) (*Crawler, error) {
	if initError != nil {
		return nil, initError
	}

	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	launcher, err := browser.NewLauncher(browser.LauncherOptions{
		ChromiumPath:        opts.ChromiumPath,
		MaxBrowsers:         opts.MaxBrowsers,
		PageMaxTimeout:      opts.PageMaxTimeout,
		ShowBrowser:         opts.ShowBrowser,
		RequestCallback:     opts.RequestCallback,
		SlowMotion:          opts.SlowMotion,
		ScopeValidator:      opts.ScopeValidator,
		ChromeUser:          opts.ChromeUser,
		Trace:               opts.Trace,
		CookieConsentBypass: opts.CookieConsentBypass,
		AutomaticScroll:     opts.AutomaticScroll,
		ScrollStep:          opts.ScrollStep,
		ScrollDelay:         opts.ScrollDelay,
		MaxScrollSteps:      opts.MaxScrollSteps,
		NoSandbox:           opts.NoSandbox,
		NoIncognito:         opts.NoIncognito,
		PageLoadStrategy:    opts.PageLoadStrategy,
		ChromeWSUrl:         opts.ChromeWSUrl,
		DOMWaitTime:         opts.DOMWaitTime,
		UserDataDir:         opts.UserDataDir,
		Proxy:               opts.Proxy,
		UserArguments:       opts.UserArguments,
	})
	if err != nil {
		return nil, err
	}

	var diagnosticsWriter diagnostics.Writer
	if opts.EnableDiagnostics {
		directory := opts.DiagnosticsDir
		if directory == "" {
			cwd, _ := os.Getwd()
			directory = filepath.Join(cwd, fmt.Sprintf("katana-diagnostics-%s", time.Now().Format(time.RFC3339)))
		}

		writer, err := diagnostics.NewWriter(directory)
		if err != nil {
			return nil, err
		}
		diagnosticsWriter = writer
		opts.DiagnosticsDir = directory
		opts.Logger.Info("Diagnostics enabled", slog.String("directory", directory))
	}

	actionJournal, err := newActionJournal(opts.ActionLogFile)
	if err != nil {
		launcher.Close()
		if diagnosticsWriter != nil {
			_ = diagnosticsWriter.Close()
		}
		return nil, errors.Wrap(err, "could not create action journal")
	}
	actionDedupKeys, err := loadActionDedupKeys(opts.ActionDedupFile)
	if err != nil {
		launcher.Close()
		if actionJournal != nil {
			_ = actionJournal.Close()
		}
		if diagnosticsWriter != nil {
			_ = diagnosticsWriter.Close()
		}
		return nil, errors.Wrap(err, "could not load action deduplication file")
	}

	crawler := &Crawler{
		launcher:               launcher,
		options:                opts,
		logger:                 opts.Logger,
		uniqueActions:          make(map[string]struct{}),
		diagnostics:            diagnosticsWriter,
		actionJournal:          actionJournal,
		actionDedupKeys:        actionDedupKeys,
		actionRetries:          make(map[string]int),
		actionPreflightRetries: make(map[string]actionPreflightRetry),
		simhashOracle:          simhash.NewOracle(),
		originRestoreFailures:  make(map[string]int),
		invalidOrigins:         make(map[string]string),
		targetFamilyFailures:   make(map[string]int),
		invalidTargetFamilies:  make(map[string]string),
	}
	return crawler, nil
}

func (c *Crawler) Close() {
	c.launcher.Close()
	if c.actionJournal != nil {
		if err := c.actionJournal.Close(); err != nil {
			c.logger.Warn("Failed to close action journal", slog.String("error", err.Error()))
		}
	}
	if c.diagnostics != nil {
		if err := c.diagnostics.Close(); err != nil {
			c.logger.Warn("Failed to close diagnostics", slog.String("error", err.Error()))
		}
	}
}

func (c *Crawler) GetCrawlGraph() *graph.CrawlGraph {
	return c.crawlGraph
}

func (c *Crawler) Crawl(URL string) error {
	c.seedURL = URL
	defer func() {
		if c.diagnostics == nil {
			return
		}
		err := c.crawlGraph.DrawGraph(filepath.Join(c.options.DiagnosticsDir, "crawl-graph.dot"))
		if err != nil {
			c.logger.Error("Failed to draw crawl graph", slog.String("error", err.Error()))
		}
	}()

	actions := []*types.Action{{
		Type:     types.ActionTypeLoadURL,
		Input:    URL,
		Depth:    0,
		OriginID: emptyPageHash,
	}}

	crawlQueue := queue.NewLinked(actions)
	c.crawlQueue = crawlQueue

	crawlGraph := graph.NewCrawlGraph()
	c.crawlGraph = crawlGraph

	// Add the initial blank state
	err := crawlGraph.AddPageState(types.PageState{
		UniqueID: emptyPageHash,
		URL:      "about:blank",
		Depth:    0,
	})
	if err != nil {
		return err
	}

	// Create a master context that will automatically cancel all page operations
	// once the per-URL crawl deadline is reached.
	parentCtx := c.options.Context
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	var (
		ctx           context.Context
		cancel        context.CancelFunc
		localDeadline bool
	)
	if c.options.MaxCrawlDuration > 0 {
		ctx, cancel = context.WithTimeout(parentCtx, c.options.MaxCrawlDuration)
		localDeadline = true
	} else {
		ctx, cancel = context.WithCancel(parentCtx)
	}
	defer cancel()

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			// Distinguish internal max-duration from external parent cancellation
			if localDeadline && parentCtx.Err() == nil {
				c.logger.Debug("Max crawl duration reached, stopping crawl")
				return nil
			}
			c.logger.Debug("Context cancelled, stopping headless crawl")
			return ctx.Err()
		default:
			// Check for too many failures
			if !c.options.ContinueOnActionFailure && c.options.MaxFailureCount > 0 && consecutiveFailures >= c.options.MaxFailureCount {
				c.logger.Warn("Too many consecutive failures, stopping crawl",
					slog.Int("failures", consecutiveFailures),
					slog.Int("max_allowed", c.options.MaxFailureCount),
					slog.Int("remaining_actions", c.crawlQueue.Size()),
				)
				return nil
			}

			action, err := crawlQueue.Get()
			if err == queue.ErrNoElementsAvailable {
				c.logger.Debug("No more actions to process")
				return nil
			}
			if err != nil {
				return err
			}
			if reason, invalid := c.invalidOrigins[action.OriginID]; invalid {
				c.recordActionEvent("attempt", "skipped", "origin state invalidated: "+reason, action, nil, nil)
				continue
			}
			familyKey := actionTargetFamilyKey(action)
			if reason, invalid := c.invalidTargetFamilies[familyKey]; familyKey != "" && invalid {
				c.recordActionEvent("attempt", "skipped", "action target family invalidated: "+reason, action, nil, nil)
				continue
			}

			depthLimit := c.options.MaxDepth
			if c.options.MaxActionDepth > 0 {
				depthLimit = c.options.MaxActionDepth
			}
			if depthLimit > 0 && action.Depth > depthLimit {
				c.recordActionEvent("attempt", "skipped", "action depth limit reached", action, nil, nil)
				continue
			}
			isInitialLoad := action.Type == types.ActionTypeLoadURL && action.Depth == 0 && action.OriginID == emptyPageHash
			actionKey := action.Hash()
			_, isPreflightRetry := c.actionPreflightRetries[actionKey]
			isRetry := !isInitialLoad && (c.actionRetries[actionKey] > 0 || isPreflightRetry)
			coverageKey := c.actionCoverageKey(action)
			if !isInitialLoad && coverageKey != "" {
				if _, confirmed := c.actionDedupKeys[coverageKey]; confirmed {
					outcome := &actionOutcome{CoverageKey: coverageKey}
					c.recordActionEvent(
						"attempt",
						"deduplicated",
						"confirmed semantic action coverage",
						action,
						outcome,
						nil,
					)
					continue
				}
			}
			if !isInitialLoad && !isRetry && c.options.MaxActionsPerCrawl > 0 && c.actionsTried >= c.options.MaxActionsPerCrawl {
				c.recordActionEvent("crawl", "stopped", "per-crawl action limit reached", action, nil, nil)
				return nil
			}

			page, err := c.launcher.GetPageFromPool()
			if err != nil {
				return err
			}

			page.Page = page.Context(ctx)
			crawlPage := page
			cancelAction := func() {}
			if !isInitialLoad && c.options.MaxActionRuntime > 0 {
				actionCtx, cancel := context.WithTimeout(ctx, c.options.MaxActionRuntime)
				cancelAction = cancel
				bounded := *page
				bounded.Page = page.Page.Context(actionCtx)
				crawlPage = &bounded
			}

			c.logger.Debug("Processing action",
				slog.String("action", action.String()),
			)
			if !isInitialLoad && !isRetry {
				c.actionsTried++
			}
			outcome := &actionOutcome{CoverageKey: coverageKey}
			c.recordActionEvent("attempt", "started", "", action, outcome, nil)

			crawlErr := c.crawlFn(ctx, action, crawlPage, page, outcome)
			cancelAction()
			if crawlErr != nil {
				err := crawlErr
				var preflightErr *actionPreflightError
				if errors.As(err, &preflightErr) && !isInitialLoad {
					if previous, alreadyDeferred := c.actionPreflightRetries[actionKey]; !alreadyDeferred {
						c.actionPreflightRetries[actionKey] = actionPreflightRetry{
							StateID: preflightErr.StateID,
						}
						c.recordActionEvent(
							"attempt", "deferred",
							"click target unavailable during fast preflight; queued once for a stable-state retry",
							action, outcome, err,
						)
						if offerErr := c.crawlQueue.Offer(action); offerErr != nil {
							return offerErr
						}
						continue
					} else {
						delete(c.actionPreflightRetries, actionKey)
						if previous.StateID == preflightErr.StateID {
							preflightErr.FinalReason = "click target remained unavailable in the same rendered state after one deferred retry"
						} else {
							preflightErr.FinalReason = "click target remained unavailable after one deferred retry"
						}
					}
				}
				if isActionRuntimeTimeout(err) && !isInitialLoad {
					if c.actionRetries[actionKey] < c.options.MaxActionRetries {
						c.actionRetries[actionKey]++
						c.recordActionEvent(
							"attempt", "retry", "action runtime limit reached",
							action, outcome, err,
						)
						if offerErr := c.crawlQueue.Offer(action); offerErr != nil {
							return offerErr
						}
						continue
					}
					delete(c.actionRetries, actionKey)
				}
				delete(c.actionPreflightRetries, actionKey)
				c.recordActionEvent("attempt", "failed", actionFailureReason(err), action, outcome, err)
				c.trackActionTargetFailure(action, outcome, err)
				if errors.Is(err, ErrOriginStateUnavailable) && action.OriginID != "" {
					c.originRestoreFailures[action.OriginID]++
					if c.originRestoreFailures[action.OriginID] >= 2 {
						reason := "origin state could not be restored twice consecutively"
						c.invalidOrigins[action.OriginID] = reason
						c.recordActionEvent("origin", "invalidated", reason, action, outcome, err)
					}
				}
				if err == ErrNoCrawlingAction {
					return nil
				}
				if errors.Is(err, ErrElementNotVisible) || errors.Is(err, ErrActionPreflightUnavailable) {
					consecutiveFailures++
					continue
				}
				var npe *rod.NoPointerEventsError
				var ish *rod.InvisibleShapeError
				if errors.As(err, &npe) || errors.As(err, &ish) {
					c.logger.Debug("Skipping action as it is not visible",
						slog.String("action", action.String()),
						slog.String("error", err.Error()),
					)
					consecutiveFailures++
					continue
				}
				var ne *rod.NavigationError
				if errors.As(err, &ne) {
					c.logger.Debug("Skipping action as navigation failed",
						slog.String("action", action.String()),
						slog.String("error", err.Error()),
					)
					consecutiveFailures++
					continue
				}
				if errors.Is(err, ErrNoNavigationPossible) {
					c.logger.Debug("Skipping action as no navigation possible", slog.String("action", action.String()))
					consecutiveFailures++
					continue
				}
				var msce *utils.MaxSleepCountError
				if errors.As(err, &msce) {
					c.logger.Debug("Skipping action as it is taking too long", slog.String("action", action.String()))
					consecutiveFailures++
					continue
				}

				c.logger.Debug("Skipping action due to site-specific error",
					slog.String("error", err.Error()),
					slog.String("action", action.String()),
				)
				consecutiveFailures++
				continue
			}

			outcome.OutcomeFingerprint = c.actionOutcomeFingerprint(outcome)
			c.recordActionEvent("attempt", "success", "", action, outcome, nil)
			delete(c.actionRetries, action.Hash())
			delete(c.actionPreflightRetries, action.Hash())
			delete(c.originRestoreFailures, action.OriginID)
			delete(c.targetFamilyFailures, actionTargetFamilyKey(action))
			consecutiveFailures = 0
		}
	}
}

var ErrNoCrawlingAction = errors.New("no more actions to crawl")
var ErrActionElementAmbiguous = errors.New("action element identity is ambiguous")
var ErrActionPreflightUnavailable = errors.New("action target unavailable during fast preflight")

type actionPreflightRetry struct {
	StateID string
}

type actionPreflightError struct {
	Cause       error
	StateID     string
	FinalReason string
}

func (e *actionPreflightError) Error() string {
	if e == nil {
		return ErrActionPreflightUnavailable.Error()
	}
	if e.FinalReason != "" {
		return e.FinalReason
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", ErrActionPreflightUnavailable, e.Cause)
	}
	return ErrActionPreflightUnavailable.Error()
}

func (e *actionPreflightError) Unwrap() error {
	return ErrActionPreflightUnavailable
}

func isStaleActionTargetFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrElementNotVisible) || errors.Is(err, ErrActionElementAmbiguous) ||
		errors.Is(err, ErrActionPreflightUnavailable) {
		return true
	}
	var noPointerEvents *rod.NoPointerEventsError
	var invisibleShape *rod.InvisibleShapeError
	return errors.As(err, &noPointerEvents) || errors.As(err, &invisibleShape)
}

// actionTargetFamilyKey groups controls that came from the same state and share
// stable framework semantics. Text, generated IDs and locators are deliberately
// excluded so a large repeated widget family can be cut without invalidating
// unrelated controls from the same page.
func actionTargetFamilyKey(action *types.Action) string {
	if action == nil || action.OriginID == "" || action.Element == nil {
		return ""
	}
	element := action.Element
	parts := []string{
		action.OriginID,
		string(action.Type),
		strings.ToUpper(strings.TrimSpace(element.TagName)),
	}
	discriminated := false
	for _, key := range []string{"data-testid", "data-test", "data-cy", "role", "type", "name"} {
		if value := normalizeActionIdentityText(element.Attributes[key]); value != "" {
			parts = append(parts, key+":"+value)
			discriminated = true
		}
	}
	if !discriminated {
		classes := strings.Fields(element.Classes)
		if len(classes) == 0 {
			return ""
		}
		sort.Strings(classes)
		parts = append(parts, "classes:"+strings.Join(classes, "."))
	}
	return sha256Hash(strings.Join(parts, "\n"))
}

// trackActionTargetFailure is a per-state, per-control-family circuit breaker.
// ContinueOnActionFailure keeps the whole crawl alive, but it should not spend
// hours resolving hundreds of stale copies of one widget. MaxFailureCount is
// reused as the threshold; zero disables this breaker as well.
func (c *Crawler) trackActionTargetFailure(action *types.Action, outcome *actionOutcome, actionErr error) {
	familyKey := actionTargetFamilyKey(action)
	if familyKey == "" {
		return
	}
	if !isStaleActionTargetFailure(actionErr) {
		delete(c.targetFamilyFailures, familyKey)
		return
	}
	threshold := c.options.MaxStaleActionFamily
	if threshold <= 0 {
		threshold = c.options.MaxFailureCount
	}
	if threshold <= 0 {
		return
	}
	if c.targetFamilyFailures == nil {
		c.targetFamilyFailures = make(map[string]int)
	}
	c.targetFamilyFailures[familyKey]++
	if c.targetFamilyFailures[familyKey] < threshold {
		return
	}
	if c.invalidTargetFamilies == nil {
		c.invalidTargetFamilies = make(map[string]string)
	}
	if _, alreadyInvalid := c.invalidTargetFamilies[familyKey]; alreadyInvalid {
		return
	}
	reason := fmt.Sprintf(
		"control family produced %d consecutive stale or non-interactable targets",
		threshold,
	)
	c.invalidTargetFamilies[familyKey] = reason
	c.recordActionEvent("target-family", "invalidated", reason, action, outcome, actionErr)
}

func actionFailureReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrElementNotVisible) {
		return "element not visible or interactable"
	}
	if errors.Is(err, ErrActionPreflightUnavailable) {
		return "element unavailable after fast preflight retry"
	}
	if errors.Is(err, ErrActionElementAmbiguous) {
		return "action element identity is ambiguous"
	}
	if errors.Is(err, ErrOriginStateUnavailable) {
		return "origin state could not be restored"
	}
	if errors.Is(err, ErrNoNavigationPossible) {
		return "origin state could not be restored"
	}
	if isActionRuntimeTimeout(err) {
		return "action runtime limit reached"
	}
	var navigationError *rod.NavigationError
	if errors.As(err, &navigationError) {
		return "navigation failed"
	}
	var sleepError *utils.MaxSleepCountError
	if errors.As(err, &sleepError) {
		return "action timed out"
	}
	return "action failed"
}

func isActionRuntimeTimeout(err error) bool {
	return err != nil && errors.Is(err, context.DeadlineExceeded)
}

func (c *Crawler) crawlFn(
	ctx context.Context,
	action *types.Action,
	page *browser.BrowserPage,
	pooledPage *browser.BrowserPage,
	outcome *actionOutcome,
) error {
	ctx = page.Page.GetContext()
	resourceSnapshotBefore, resourceSnapshotOK := capturePageResourceSnapshot(
		page,
		c.options.PageMaxTimeout,
	)
	targetsBefore := map[proto.TargetTargetID]struct{}{}
	if c.options.CaptureNewTabs {
		targetsBefore = pageTargetIDs(page, c.options.PageMaxTimeout)
	}
	defer func() {
		if c.options.CaptureNewTabs {
			outcome.PopupURLs, outcome.Popups = c.collectActionPopups(
				page,
				targetsBefore,
				action,
			)
		}
		completeActionOutcome(
			page,
			outcome,
			resourceSnapshotBefore,
			resourceSnapshotOK,
			c.options.PageMaxTimeout,
		)
		// A page whose action context expired can still contain a running script
		// or a target waiting for the debugger. Never recycle that target: close
		// only Katana's own page and let the next attempt use a clean one.
		if page.Page.GetContext().Err() != nil {
			c.launcher.DiscardBrowserPage(pooledPage)
			return
		}
		c.launcher.PutBrowserToPool(pooledPage)
	}()

	currentPageHash, _, err := getPageHash(page, c.options.PageMaxTimeout)
	if err != nil {
		outcome.StateCaptureFailed = true
		return err
	}
	outcome.BeforeStateID = currentPageHash
	if info, infoErr := page.Info(); infoErr == nil {
		outcome.BeforeURL = info.URL
	}

	c.logger.Debug("Processing action - current state",
		slog.String("current_page_hash", currentPageHash),
		slog.String("action_origin_id", action.OriginID),
		slog.String("action", action.String()),
	)

	needsRestore := action.OriginID != "" && action.OriginID != currentPageHash
	if action.OriginID != "" && !needsRestore && !actionTargetVisible(page, action) {
		// DOM normalization intentionally ignores many volatile attributes. A
		// previous action can therefore hide or replace a control without
		// changing the normalized state hash. Restore the recorded branch when
		// the concrete target is no longer usable.
		needsRestore = true
	}
	if needsRestore {
		c.logger.Debug("Need to navigate back to origin",
			slog.String("from", currentPageHash),
			slog.String("to", action.OriginID),
		)
		newPageHash, err := c.navigateBackToStateOrigin(action, page, currentPageHash)
		if err != nil {
			return err
		}
		// Refresh the page hash
		currentPageHash = newPageHash
	}
	// The journal's "before" state describes the branch that will actually be
	// clicked, not the stale page that happened to be left in the pool.
	outcome.BeforeStateID = currentPageHash
	if info, infoErr := page.Info(); infoErr == nil {
		outcome.BeforeURL = info.URL
	}
	resourceSnapshotBefore, resourceSnapshotOK = capturePageResourceSnapshot(
		page,
		c.options.PageMaxTimeout,
	)
	if c.options.CaptureNewTabs {
		targetsBefore = pageTargetIDs(page, c.options.PageMaxTimeout)
	}

	// FIXME: TODO: Restrict the navigation using scope manager and only
	// proceed with actions if the scope is allowed

	// Check the action and do actions based on action type
	if c.diagnostics != nil {
		if err := c.diagnostics.LogAction(action); err != nil {
			return err
		}
	}
	if err := c.executeCrawlStateAction(action, page); err != nil {
		var preflightErr *actionPreflightError
		if errors.As(err, &preflightErr) {
			preflightErr.StateID = currentPageHash
			// No click was dispatched, so the before-state is also the exact
			// after-state. Avoid a second expensive DOM hash in the deferred path.
			outcome.AfterStateID = currentPageHash
			outcome.AfterURL = outcome.BeforeURL
		}
		return err
	}
	outcome.Executed = true

	// Check for captcha pages after navigation and attempt to solve them.
	// On success, wait for the page to settle and re-enter crawlFn so navigation
	// discovery runs on the post-solve page instead of the captcha page.
	if c.options.CaptchaHandler != nil {
		html, htmlErr := page.HTML()
		if htmlErr == nil {
			handled, solveErr := c.options.CaptchaHandler.HandleIfCaptcha(ctx, page.Page, html)
			if solveErr != nil {
				gologger.Warning().Msgf("captcha solving failed: %s", solveErr)
			}
			if handled && solveErr == nil {
				_ = page.WaitPageLoadHeurisitics()
			}
			if handled {
				// Skip navigation discovery on captcha pages — the discovered
				// links/forms belong to the captcha widget, not the real page.
				return nil
			}
		}
	}

	if !c.loggedIn && c.options.AuthUsername != "" && c.options.DitClassifier != nil {
		if info, err := page.Info(); err == nil && (c.options.ScopeValidator == nil || c.options.ScopeValidator(info.URL)) {
			if html, htmlErr := page.HTML(); htmlErr == nil {
				if c.tryAutoLogin(page, html) {
					_ = page.WaitPageLoadHeurisitics()
				}
			}
		}
	}

	pageState, err := newPageState(page, action, c.options.PageMaxTimeout)
	if err != nil {
		outcome.StateCaptureFailed = true
		return err
	}
	pageState.OriginID = currentPageHash

	if c.options.ScopeValidator != nil {
		if !c.options.ScopeValidator(pageState.URL) {
			c.logger.Debug("Skipping navigation collection - current page is out of scope",
				slog.String("url", pageState.URL),
			)
			if c.crawlQueue.Size() == 0 {
				return ErrNoCrawlingAction
			}
			return nil
		}
	}

	navigations, err := page.FindNavigations()
	if err != nil {
		return err
	}
	applyNavigationStateIdentity(pageState, navigations)
	repeatedState := action.Type != types.ActionTypeLoadURL && pageState.UniqueID == currentPageHash
	if action.Type != types.ActionTypeLoadURL && !repeatedState && c.options.AutomaticScroll {
		// The cheap no-scroll state above is enough to recognize no-op/repeated
		// outcomes. New states still receive the full bounded scroll before their
		// definitive DOM/action inventory, preserving lazy-load coverage.
		if err := page.AutomaticScroll(c.options.PageMaxTimeout); err != nil {
			if isActionRuntimeTimeout(err) {
				return err
			}
			c.logger.Debug("Post-action automatic scroll failed", slog.String("error", err.Error()))
		}
		if err := page.WaitPageLoadHeurisiticsWithoutScroll(); err != nil {
			return err
		}
		pageState, err = newPageState(page, action, c.options.PageMaxTimeout)
		if err != nil {
			outcome.StateCaptureFailed = true
			return err
		}
		pageState.OriginID = currentPageHash
		navigations, err = page.FindNavigations()
		if err != nil {
			return err
		}
		applyNavigationStateIdentity(pageState, navigations)
		repeatedState = pageState.UniqueID == currentPageHash
	}
	action.ResultID = pageState.UniqueID
	outcome.AfterStateID = pageState.UniqueID
	outcome.AfterURL = pageState.URL
	outcome.DOMChanged = outcome.BeforeStateID != "" && outcome.BeforeStateID != outcome.AfterStateID
	if c.diagnostics != nil {
		if err := c.diagnostics.LogPageState(pageState, diagnostics.PostActionPageState); err != nil {
			return err
		}
	}

	// Log navigations for diagnostics
	if c.diagnostics != nil {
		screenshotState, err := page.Screenshot(false, &proto.PageCaptureScreenshot{
			Format: proto.PageCaptureScreenshotFormatPng,
		})
		if err != nil {
			c.logger.Error("Failed to take screenshot", slog.String("error", err.Error()))
		}
		if err := c.diagnostics.LogPageStateScreenshot(pageState.UniqueID, screenshotState); err != nil {
			c.logger.Error("Failed to log page state screenshot", slog.String("error", err.Error()))
		}
		if err := c.diagnostics.LogNavigations(pageState.UniqueID, navigations); err != nil {
			c.logger.Error("Failed to log navigations", slog.String("error", err.Error()))
		}
	}

	if !repeatedState {
		if err := c.enqueueNavigations(pageState, navigations); err != nil {
			return err
		}
	}

	err = c.crawlGraph.AddPageState(*pageState)
	if err != nil {
		return err
	}

	return nil
}

func actionTargetVisible(page *browser.BrowserPage, action *types.Action) bool {
	if action == nil || action.Element == nil {
		return true
	}
	_, current, err := resolveActionElement(page, action.Element, 500*time.Millisecond)
	if err != nil {
		return false
	}
	return current.Visible
}

var htmlTagPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)

// resolveActionElement first tries the captured locator, then falls back to a
// unique semantic match on the same document. Component frameworks regularly
// regenerate ancestor IDs, so a selector can become stale after restoring the
// exact same SPA route. Every resolved node is identity-checked before use;
// ambiguous matches fail closed instead of clicking the wrong control.
func resolveActionElement(page *browser.BrowserPage, target *types.HTMLElement, timeout time.Duration) (*rod.Element, *types.HTMLElement, error) {
	if page == nil || target == nil {
		return nil, nil, ErrElementNotVisible
	}
	fastTimeout := timeout
	if fastTimeout <= 0 || fastTimeout > 750*time.Millisecond {
		fastTimeout = 750 * time.Millisecond
	}
	if exact, err := page.GetElementWithTimeout(target, fastTimeout); err == nil {
		if current, dataErr := page.GetResolvedElementData(exact); dataErr == nil && isElementMatch(current, target) {
			return exact, current, nil
		}
	}

	tag := strings.ToLower(strings.TrimSpace(target.TagName))
	if !htmlTagPattern.MatchString(tag) {
		return nil, nil, ErrElementNotVisible
	}
	candidates, err := page.GetAllElementsWithTimeout(tag, timeout)
	if err != nil {
		return nil, nil, err
	}
	matches := make([]*types.HTMLElement, 0, 2)
	for _, candidate := range candidates {
		if !sameActionDocument(target.DocumentURL, candidate.DocumentURL) || !isElementMatch(candidate, target) {
			continue
		}
		matches = append(matches, candidate)
		if len(matches) > 1 {
			return nil, nil, fmt.Errorf("%w after DOM update", ErrActionElementAmbiguous)
		}
	}
	if len(matches) != 1 {
		return nil, nil, ErrElementNotVisible
	}
	resolved, err := page.GetElementWithTimeout(matches[0], timeout)
	if err != nil {
		return nil, nil, err
	}
	current, err := page.GetResolvedElementData(resolved)
	if err != nil || !isElementMatch(current, target) {
		return nil, nil, ErrElementNotVisible
	}
	return resolved, current, nil
}

func sameActionDocument(expected string, actual string) bool {
	expected = strings.TrimSpace(expected)
	actual = strings.TrimSpace(actual)
	if expected == "" || expected == actual {
		return true
	}
	if actual == "" {
		return false
	}
	expectedURL, expectedErr := url.Parse(expected)
	actualURL, actualErr := url.Parse(actual)
	if expectedErr != nil || actualErr != nil {
		return false
	}
	return strings.EqualFold(expectedURL.Scheme, actualURL.Scheme) &&
		strings.EqualFold(expectedURL.Host, actualURL.Host) &&
		expectedURL.EscapedPath() == actualURL.EscapedPath() &&
		expectedURL.RawQuery == actualURL.RawQuery &&
		expectedURL.Fragment == actualURL.Fragment
}

// linkFallbackAction converts a temporarily non-interactable anchor into a
// normal in-scope load action. This preserves coverage for collapsed SPA menu
// links without using JavaScript to bypass the application's click safety.
func (c *Crawler) linkFallbackAction(action *types.Action) *types.Action {
	if action == nil || action.Element == nil || !strings.EqualFold(action.Element.TagName, "a") {
		return nil
	}
	href := strings.TrimSpace(action.Element.Attributes["href"])
	if href == "" {
		return nil
	}
	reference, err := url.Parse(href)
	if err != nil {
		return nil
	}
	base, err := url.Parse(strings.TrimSpace(action.Element.DocumentURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	resolved := base.ResolveReference(reference)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil
	}
	if resolved.Host != "" && resolved.Path == "" {
		// Browsers normalize https://host#/route to https://host/#/route.
		// Persist the canonical form so SPA route identity stays stable.
		resolved.Path = "/"
	}
	resolvedURL := resolved.String()
	if c.options.ScopeValidator != nil && !c.options.ScopeValidator(resolvedURL) {
		return nil
	}
	fallback := &types.Action{
		Type:     types.ActionTypeLoadURL,
		Input:    resolvedURL,
		Depth:    action.Depth,
		OriginID: action.OriginID,
	}
	if isDeniedAction(fallback) {
		return nil
	}
	return fallback
}

func (c *Crawler) enqueueNavigations(pageState *types.PageState, navigations []*types.Action) error {
	inventory := stateActionInventory{}
	for _, nav := range navigations {
		if nav != nil && nav.Type != types.ActionTypeLoadURL {
			inventory.Candidates++
		}
	}
	deferredSamples := 0
	skippedSamples := 0
	duplicateSamples := 0
	const journalSampleLimit = 10
	for index, nav := range navigations {
		if nav == nil {
			continue
		}
		nav.OriginID = pageState.UniqueID
		nav.Depth = pageState.Depth

		if isDeniedAction(nav) {
			if nav.Type != types.ActionTypeLoadURL {
				inventory.Denied++
			}
			c.logger.Debug("Skipping potentially destructive navigation",
				slog.String("action", nav.String()),
			)
			c.recordActionEvent("discovered", "denied", "deny policy matched", nav, nil, nil)
			continue
		}
		if nav.Type == types.ActionTypeFillForm && !c.options.AutomaticFormFill {
			inventory.Skipped++
			if skippedSamples < journalSampleLimit {
				c.recordActionEvent("discovered", "skipped", "automatic form fill disabled", nav, nil, nil)
				skippedSamples++
			}
			continue
		}
		if nav.Element != nil {
			if nav.Element.Disabled {
				inventory.Skipped++
				if skippedSamples < journalSampleLimit {
					c.recordActionEvent("discovered", "skipped", "element disabled", nav, nil, nil)
					skippedSamples++
				}
				continue
			}
			if !nav.Element.Visible {
				// Do not put deferred controls in the global uniqueness set. A
				// parent action may make the same control visible in a later state.
				inventory.Deferred++
				if deferredSamples < journalSampleLimit {
					c.recordActionEvent("discovered", "deferred", "element not currently visible", nav, nil, nil)
					deferredSamples++
				}
				continue
			}
			if nav.Element.PointerEventsNone {
				// Do not poison the click identity: a parent menu action may make
				// it interactable in a later state. Anchors still receive a safe
				// direct-navigation fallback so their route is not lost.
				inventory.Deferred++
				if deferredSamples < journalSampleLimit {
					c.recordActionEvent("discovered", "deferred", "element has pointer-events none", nav, nil, nil)
					deferredSamples++
				}
				fallback := c.linkFallbackAction(nav)
				if fallback == nil {
					continue
				}
				nav = fallback
			}
		}
		if c.options.MaxActionsPerState > 0 && inventory.Queued >= c.options.MaxActionsPerState {
			inventory.Truncated = true
			for _, omitted := range navigations[index:] {
				if omitted != nil && omitted.Type != types.ActionTypeLoadURL {
					inventory.Omitted++
				}
			}
			c.recordActionEvent("discovered", "skipped", "per-state action limit reached", nav, nil, nil)
			break
		}

		actionHash := nav.Hash()
		if _, ok := c.uniqueActions[actionHash]; ok {
			if nav.Type != types.ActionTypeLoadURL {
				inventory.Duplicates++
			}
			if duplicateSamples < journalSampleLimit {
				c.recordActionEvent("discovered", "duplicate", "action already queued for this state", nav, nil, nil)
				duplicateSamples++
			}
			continue
		}
		c.uniqueActions[actionHash] = struct{}{}
		inventory.Queued++
		if nav.Type != types.ActionTypeLoadURL {
			inventory.InteractiveQueued++
		}

		c.logger.Debug("Got new navigation", slog.Any("navigation", nav))
		c.recordActionEvent("discovered", "queued", "", nav, nil, nil)
		if err := c.crawlQueue.Offer(nav); err != nil {
			return err
		}
	}
	c.recordStateInventory(pageState, inventory)
	return nil
}

var ErrElementNotVisible = errors.New("element not visible")

func (c *Crawler) executeCrawlStateAction(action *types.Action, page *browser.BrowserPage) error {
	return runWithActionHooks(c.options.Hooks, page, action, func() error {
		return c.dispatchCrawlAction(action, page)
	})
}

type clickableActionTarget struct {
	current *types.HTMLElement
	point   *proto.Point
}

// resolveClickableActionTarget performs every read-only check required before
// dispatching a physical click. In preflight mode all locator enumeration,
// scrolling, visibility and hit-testing share one short context deadline.
// The mouse event itself deliberately runs outside this context: timing out a
// click whose JavaScript handler already started could otherwise cause an
// unsafe duplicate retry.
func resolveClickableActionTarget(
	page *browser.BrowserPage,
	action *types.Action,
	timeout time.Duration,
	preflight bool,
) (*clickableActionTarget, error) {
	if page == nil || action == nil || action.Element == nil {
		return nil, ErrElementNotVisible
	}
	workingPage := page
	if preflight {
		ctx, cancel := context.WithTimeout(page.Page.GetContext(), timeout)
		defer cancel()
		bounded := *page
		bounded.Page = page.Page.Context(ctx)
		workingPage = &bounded
	}

	element, current, err := resolveActionElement(workingPage, action.Element, timeout)
	if err != nil {
		return nil, err
	}
	if current.PointerEventsNone {
		return &clickableActionTarget{current: current}, nil
	}

	elementForChecks := element
	if !preflight {
		elementForChecks = element.Timeout(timeout)
	}
	// Rod's ScrollIntoView waits for requestAnimationFrame and can hang on a
	// background external-Chrome tab. The DOM primitive is synchronous and the
	// following Rod hit-test still protects against overlays.
	if _, err := elementForChecks.Eval(`() => {
		this.scrollIntoView({block: 'center', inline: 'center'});
		return true;
	}`); err != nil {
		return nil, err
	}
	visible, err := elementForChecks.Visible()
	if err != nil {
		return nil, err
	}
	if !visible {
		return nil, ErrElementNotVisible
	}
	interactable, err := elementForChecks.Interactable()
	if err != nil {
		var covered *rod.CoveredError
		if errors.As(err, &covered) {
			return nil, ErrElementNotVisible
		}
		return nil, err
	}
	if interactable == nil {
		return nil, ErrElementNotVisible
	}
	enabled, err := elementForChecks.Eval(`() => !this.disabled && this.getAttribute('aria-disabled') !== 'true'`)
	if err != nil {
		return nil, err
	}
	if !enabled.Value.Bool() {
		return nil, ErrElementNotVisible
	}
	return &clickableActionTarget{current: current, point: interactable}, nil
}

func (c *Crawler) clickPreflightError(action *types.Action, started time.Time, cause error) error {
	c.recordActionEvent(
		"preflight", "unavailable",
		fmt.Sprintf("target checks stopped after %s", time.Since(started).Round(time.Millisecond)),
		action, nil, cause,
	)
	return &actionPreflightError{Cause: cause}
}

func (c *Crawler) dispatchCrawlAction(action *types.Action, page *browser.BrowserPage) error {
	var err error
	switch action.Type {
	case types.ActionTypeLoadURL:
		// Apply a timeout to every critical Rod call.
		pTimeout := page.Timeout(c.options.PageMaxTimeout)

		if err := pTimeout.Navigate(action.Input); err != nil {
			return err
		}
		if err = page.WaitPageLoadHeurisitics(); err != nil {
			return err
		}
	case types.ActionTypeFillForm:
		if err := c.processForm(page, action.Form); err != nil {
			return err
		}
		if err = page.WaitPageLoadHeurisiticsWithoutScroll(); err != nil {
			return err
		}
	case types.ActionTypeLeftClick, types.ActionTypeLeftClickDown:
		preflight := c.options.ActionPreflightTimeout > 0
		targetTimeout := c.options.PageMaxTimeout
		if preflight {
			targetTimeout = c.options.ActionPreflightTimeout
		}
		preflightStarted := time.Now()
		target, err := resolveClickableActionTarget(page, action, targetTimeout, preflight)
		if err != nil {
			if preflight && page.Page.GetContext().Err() == nil {
				return c.clickPreflightError(action, preflightStarted, err)
			}
			return err
		}

		// The element may have become non-interactable after it was queued.
		// A safe anchor can still be covered by loading its in-scope href directly.
		if target.current.PointerEventsNone {
			fallbackSource := *action
			fallbackSource.Element = target.current
			if fallback := c.linkFallbackAction(&fallbackSource); fallback != nil {
				c.recordActionEvent("fallback", "navigated", "element has pointer-events none", fallback, nil, nil)
				pTimeout := page.Timeout(c.options.PageMaxTimeout)
				if err := pTimeout.Navigate(fallback.Input); err != nil {
					return err
				}
				return page.WaitPageLoadHeurisiticsWithoutScroll()
			}
			if preflight {
				return c.clickPreflightError(action, preflightStarted, ErrElementNotVisible)
			}
			return ErrElementNotVisible
		}
		if preflight {
			c.recordActionEvent(
				"preflight", "passed",
				fmt.Sprintf("target checks completed in %s", time.Since(preflightStarted).Round(time.Millisecond)),
				action, nil, nil,
			)
		}

		var (
			activityBaseline browser.ActionActivitySnapshot
			activityErr      error
		)
		if c.options.ActionSignalTimeout > 0 {
			activityBaseline, activityErr = page.CaptureActionActivity()
		}
		boundedPage := page.Timeout(c.options.PageMaxTimeout)
		if err := boundedPage.Mouse.MoveTo(*target.point); err != nil {
			return err
		}
		if err := boundedPage.Mouse.Click(proto.InputMouseButtonLeft, 1); err != nil {
			return err
		}
		if c.options.ActionSignalTimeout > 0 && activityErr == nil {
			progressTimeout := time.Duration(c.options.DOMWaitTime) * time.Second
			waitResult, waitErr := page.WaitForActionActivity(
				activityBaseline,
				c.options.ActionSignalTimeout,
				c.options.ActionQuietPeriod,
				progressTimeout,
			)
			c.recordActionEvent(
				"post-action-wait", waitResult.Reason,
				fmt.Sprintf("signal=%t duration=%s", waitResult.SignalObserved, waitResult.Elapsed.Round(time.Millisecond)),
				action, nil, waitErr,
			)
			return waitErr
		}
		if activityErr != nil && c.options.ActionSignalTimeout > 0 {
			c.recordActionEvent(
				"post-action-wait", "fallback",
				"activity baseline unavailable; using configured page-load strategy",
				action, nil, activityErr,
			)
		}
		return page.WaitPageLoadHeurisiticsWithoutScroll()
	default:
		return fmt.Errorf("unknown action type: %v", action.Type)
	}

	return nil
}

func (c *Crawler) tryAutoLogin(page *browser.BrowserPage, html string) bool {
	pageResult, err := c.options.DitClassifier.ExtractPageType(html)
	if err != nil || pageResult == nil {
		return false
	}

	for _, form := range pageResult.Forms {
		if form.Type != "login" {
			continue
		}

		pageURL := ""
		if info, err := page.Info(); err == nil {
			pageURL = info.URL
		}
		c.logger.Info("Login form detected, attempting auto-login",
			slog.String("url", pageURL),
		)

		filled := false
		for fieldName, fieldType := range form.Fields {
			var value string
			switch fieldType {
			case "password":
				value = c.options.AuthPassword
			default:
				value = c.options.AuthUsername
			}

			escapedName := strings.ReplaceAll(fieldName, `\`, `\\`)
			escapedName = strings.ReplaceAll(escapedName, `'`, `\'`)
			el, err := page.Element("input[name='" + escapedName + "']")
			if err != nil {
				c.logger.Debug("Could not find login field", slog.String("field", fieldName))
				continue
			}
			if err := el.Input(value); err != nil {
				c.logger.Debug("Could not fill login field", slog.String("field", fieldName))
				continue
			}
			filled = true
		}

		if !filled {
			continue
		}

		if submitted := c.submitLoginForm(page); submitted {
			c.loggedIn = true
			c.logger.Info("Auto-login submitted successfully")
			return true
		}
	}
	return false
}

func (c *Crawler) submitLoginForm(page *browser.BrowserPage) bool {
	selectors := []string{
		"form button[type='submit']",
		"form input[type='submit']",
		"form button:not([type])",
	}
	for _, sel := range selectors {
		if el, err := page.Element(sel); err == nil {
			if err := el.Click(proto.InputMouseButtonLeft, 1); err == nil {
				return true
			}
		}
	}
	return false
}

// Keep this list deliberately narrow. Word-like boundaries avoid blocking
// unrelated labels such as "payload" or "payment settings".
var deniedActionPattern = regexp.MustCompile(`(?i)(^|[^a-z0-9])(log[\s_-]*out|sign[\s_-]*out|delete|remove|pay)([^a-z0-9]|$)`)
var camelCaseBoundaryPattern = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func containsDeniedAction(value string) bool {
	return deniedActionPattern.MatchString(
		camelCaseBoundaryPattern.ReplaceAllString(value, `$1 $2`),
	)
}

func isDeniedElement(element *types.HTMLElement) bool {
	if element == nil {
		return false
	}
	if containsDeniedAction(element.TextContent) ||
		containsDeniedAction(element.ID) ||
		containsDeniedAction(element.Classes) {
		return true
	}
	// Evaluate user-facing and navigation attributes, not arbitrary inline
	// JavaScript or the complete outerHTML. Calls such as element.remove() are
	// common UI implementation details and do not mean that the control itself
	// is a destructive "Remove" action.
	for _, name := range []string{
		"href", "action", "formaction", "name", "title", "aria-label",
		"aria-labelledby", "data-action", "data-testid", "data-test", "data-cy",
	} {
		if containsDeniedAction(element.Attributes[name]) {
			return true
		}
	}
	return false
}

func isDeniedAction(action *types.Action) bool {
	if action == nil {
		return false
	}
	if containsDeniedAction(action.Input) || isDeniedElement(action.Element) {
		return true
	}
	if action.Form == nil {
		return false
	}
	if containsDeniedAction(action.Form.Action) {
		return true
	}
	for _, element := range action.Form.Elements {
		if isDeniedElement(element) {
			return true
		}
	}
	return false
}

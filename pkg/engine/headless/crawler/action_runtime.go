package crawler

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/katana/pkg/engine/headless/browser"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
)

type pageResourceSnapshot struct {
	Count int     `json:"count"`
	NowMS float64 `json:"now_ms"`
}

func capturePageResourceSnapshot(page *browser.BrowserPage, timeout time.Duration) (pageResourceSnapshot, bool) {
	bounded := page.Page
	if timeout > 0 {
		bounded = page.Timeout(timeout)
	}
	result, err := bounded.Eval(`() => ({
		count: performance.getEntriesByType('resource').length,
		now_ms: Date.now(),
	})`)
	if err != nil || result == nil {
		return pageResourceSnapshot{}, false
	}
	var snapshot pageResourceSnapshot
	if err := result.Value.Unmarshal(&snapshot); err != nil || snapshot.NowMS <= 0 {
		return pageResourceSnapshot{}, false
	}
	return snapshot, true
}

func completeActionOutcome(
	page *browser.BrowserPage,
	outcome *actionOutcome,
	resourcesBefore pageResourceSnapshot,
	resourceSnapshotOK bool,
	timeout time.Duration,
) {
	if outcome == nil {
		return
	}
	if info, err := page.Info(); err == nil {
		outcome.AfterURL = info.URL
	}
	if outcome.AfterStateID == "" && !outcome.StateCaptureFailed {
		if stateID, _, err := getPageHash(page, timeout); err == nil {
			outcome.AfterStateID = stateID
		}
	}
	if outcome.BeforeStateID != "" && outcome.AfterStateID != "" {
		outcome.DOMChanged = outcome.BeforeStateID != outcome.AfterStateID
	}
	if !resourceSnapshotOK {
		outcome.NetworkCaptureFailed = true
		return
	}
	bounded := page.Page
	if timeout > 0 {
		bounded = page.Timeout(timeout)
	}
	result, err := bounded.Eval(`(startedAt) => {
		const origin = performance.timeOrigin || (Date.now() - performance.now());
		return performance.getEntriesByType('resource')
			.filter(entry => origin + entry.startTime >= startedAt - 5)
			.map(entry => String(entry.name || ''))
			.filter(Boolean);
	}`, resourcesBefore.NowMS)
	if err != nil || result == nil {
		outcome.NetworkCaptureFailed = true
		return
	}
	var resourceURLs []string
	if err := result.Value.Unmarshal(&resourceURLs); err != nil {
		outcome.NetworkCaptureFailed = true
		return
	}
	sort.Strings(resourceURLs)
	outcome.NetworkRequests = len(resourceURLs)
	outcome.NetworkFingerprint = sha256Hash(strings.Join(resourceURLs, "\x00"))
}

func pageTargetIDs(page *browser.BrowserPage, timeout time.Duration) map[proto.TargetTargetID]struct{} {
	result := make(map[proto.TargetTargetID]struct{})
	bounded := page.Browser
	if timeout > 0 {
		bounded = page.Browser.Timeout(timeout)
	}
	pages, err := bounded.Pages()
	if err != nil {
		return result
	}
	for _, candidate := range pages {
		result[candidate.TargetID] = struct{}{}
	}
	return result
}

type popupCandidate struct {
	page *rod.Page
	info *proto.TargetTargetInfo
}

func (c *Crawler) collectActionPopups(
	page *browser.BrowserPage,
	before map[proto.TargetTargetID]struct{},
	parent *types.Action,
) ([]string, []actionPopupSnapshot) {
	// Give target=_blank/window.open handlers a short opportunity to publish
	// the target and its final URL. The normal post-click readiness wait has
	// already handled ordinary navigations.
	time.Sleep(100 * time.Millisecond)
	popupTimeout := c.options.PageMaxTimeout
	if popupTimeout <= 0 || popupTimeout > 3*time.Second {
		popupTimeout = 3 * time.Second
	}
	pages, err := page.Browser.Timeout(popupTimeout).Pages()
	if err != nil {
		return nil, nil
	}

	newPages := make(map[proto.TargetTargetID]popupCandidate)
	for _, candidate := range pages {
		if candidate.TargetID == page.TargetID {
			continue
		}
		if _, existed := before[candidate.TargetID]; existed {
			continue
		}
		info, infoErr := candidate.Timeout(popupTimeout).Info()
		if infoErr != nil {
			continue
		}
		newPages[candidate.TargetID] = popupCandidate{page: candidate, info: info}
	}

	// Only adopt targets whose opener is the action page (or another adopted
	// child). This prevents an external-Chrome user tab opened at the same time
	// from ever being treated as Katana-owned.
	owned := map[proto.TargetTargetID]struct{}{page.TargetID: {}}
	changed := true
	for changed {
		changed = false
		for targetID, candidate := range newPages {
			if _, alreadyOwned := owned[targetID]; alreadyOwned {
				continue
			}
			if _, openerOwned := owned[candidate.info.OpenerID]; openerOwned {
				owned[targetID] = struct{}{}
				changed = true
			}
		}
	}

	var popupURLs []string
	var popupSnapshots []actionPopupSnapshot
	for targetID, candidate := range newPages {
		if _, isOwned := owned[targetID]; !isOwned {
			continue
		}
		info := candidate.info
		for attempt := 0; attempt < 10 && (info.URL == "" || info.URL == "about:blank"); attempt++ {
			time.Sleep(100 * time.Millisecond)
			if refreshed, refreshErr := candidate.page.Timeout(popupTimeout).Info(); refreshErr == nil {
				info = refreshed
			}
		}

		html := ""
		if rendered, htmlErr := candidate.page.Timeout(2 * time.Second).HTML(); htmlErr == nil {
			html = rendered
		}
		snapshot := actionPopupSnapshot{URL: info.URL, Title: info.Title}
		if c.actionJournal != nil {
			snapshot = c.actionJournal.storePopupDOM(info.URL, info.Title, html)
		}
		if info.URL != "" && info.URL != "about:blank" {
			popupURLs = append(popupURLs, info.URL)
		}
		popupSnapshots = append(popupSnapshots, snapshot)

		popupAction := &types.Action{
			Type:     types.ActionTypeLoadURL,
			Input:    info.URL,
			Depth:    parent.Depth + 1,
			OriginID: parent.ResultID,
		}
		popupOutcome := &actionOutcome{
			AfterURL:  info.URL,
			PopupURLs: []string{info.URL},
			Popups:    []actionPopupSnapshot{snapshot},
		}
		c.recordActionEvent("popup", "captured", "action-owned target", popupAction, popupOutcome, nil)
		c.schedulePopupAction(popupAction)
		_ = candidate.page.Timeout(popupTimeout).Close()
	}
	return popupURLs, popupSnapshots
}

func (c *Crawler) schedulePopupAction(action *types.Action) {
	if action == nil || action.Input == "" {
		return
	}
	parsed, err := url.Parse(action.Input)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		c.recordActionEvent("popup", "skipped", "popup URL is not HTTP(S)", action, nil, err)
		return
	}
	if isDeniedAction(action) {
		c.recordActionEvent("popup", "denied", "deny policy matched", action, nil, nil)
		return
	}
	if c.options.ScopeValidator != nil && !c.options.ScopeValidator(action.Input) {
		c.recordActionEvent("popup", "observed", "popup URL is outside navigation scope", action, nil, nil)
		return
	}
	actionHash := action.Hash()
	if _, exists := c.uniqueActions[actionHash]; exists {
		c.recordActionEvent("popup", "duplicate", "popup URL already queued", action, nil, nil)
		return
	}
	c.uniqueActions[actionHash] = struct{}{}
	if err := c.crawlQueue.Offer(action); err != nil {
		c.recordActionEvent("popup", "failed", "could not queue popup URL", action, nil, err)
		return
	}
	c.recordActionEvent("popup", "queued", "", action, nil, nil)
}

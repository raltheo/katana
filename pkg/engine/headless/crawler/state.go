package crawler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	graphlib "github.com/dominikbraun/graph"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/katana/pkg/engine/headless/browser"
	"github.com/projectdiscovery/katana/pkg/engine/headless/crawler/diagnostics"
	"github.com/projectdiscovery/katana/pkg/engine/headless/crawler/normalizer/simhash"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
)

var emptyPageHash = sha256Hash("")

const simhashThreshold = 2 // Allow up to 2 bits difference

func (c *Crawler) isCorrectNavigation(page *browser.BrowserPage, action *types.Action) (string, *types.PageState, error) {
	currentPageHash, pageState, err := getPageHash(page, c.options.PageMaxTimeout)
	if err != nil {
		return "", nil, err
	}

	if currentPageHash == action.OriginID {
		if action.Element != nil && !actionTargetVisible(page, action) {
			return "", pageState, fmt.Errorf("origin state hash matched but action target is unavailable")
		}
		return currentPageHash, pageState, nil
	}

	// Get the origin page state to compare SimHash
	originPageState, err := c.crawlGraph.GetPageState(action.OriginID)
	if err != nil {
		return "", pageState, fmt.Errorf("failed to get origin page state: %w", err)
	}

	if pageState != nil && originPageState != nil {
		distance := simhash.Distance(pageState.SimHash, originPageState.SimHash)
		if distance <= simhashThreshold {
			// Similar DOMs are not interchangeable when restoring an action
			// branch. A collapsed menu can differ by only a few SimHash bits
			// while its child action is absent. Require the concrete target to
			// exist and be visible before accepting a fuzzy state match.
			if !sameInteractiveState(pageState, originPageState) {
				return "", pageState, fmt.Errorf("similar page has a different interactive state")
			}
			if action.Element != nil {
				_, currentElement, elementErr := resolveActionElement(page, action.Element, 750*time.Millisecond)
				if elementErr != nil || !currentElement.Visible {
					return "", pageState, fmt.Errorf("similar page does not contain the origin action target")
				}
			}
			c.logger.Debug("Page is similar enough to origin, proceeding",
				slog.String("current_hash", currentPageHash),
				slog.String("origin_hash", action.OriginID),
				slog.Uint64("simhash_distance", uint64(distance)),
			)
			// Treat this page as the origin state to avoid creating a new vertex
			return originPageState.UniqueID, pageState, nil
		}
	}

	return "", pageState, fmt.Errorf("failed to navigate back to origin page: %s != %s", currentPageHash, action.OriginID)
}

// sameInteractiveState prevents SimHash's intentionally fuzzy DOM comparison
// from collapsing an open menu/dialog into its closed origin. Empty signatures
// remain compatible with graph vertices produced by older/non-interactive
// crawl paths.
func sameInteractiveState(current, origin *types.PageState) bool {
	if current == nil || origin == nil {
		return false
	}
	if current.ActionSignature == "" || origin.ActionSignature == "" {
		return true
	}
	return current.ActionSignature == origin.ActionSignature
}

func getPageHash(page *browser.BrowserPage, timeout time.Duration) (string, *types.PageState, error) {
	pageState, err := newPageState(page, nil, timeout)
	if err == ErrEmptyPage {
		return emptyPageHash, nil, nil
	}
	if err != nil {
		return "", nil, errors.Wrap(err, "could not get page state")
	}
	navigations, err := page.FindNavigations()
	if err != nil {
		return "", nil, errors.Wrap(err, "could not inventory page actions")
	}
	applyNavigationStateIdentity(pageState, navigations)
	return pageState.UniqueID, pageState, nil
}

var ErrEmptyPage = errors.New("page is empty")

func newPageState(page *browser.BrowserPage, action *types.Action, timeout time.Duration) (*types.PageState, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	bounded := *page
	bounded.Page = page.Timeout(timeout)
	pageInfo, err := bounded.Info()
	if err != nil {
		return nil, errors.Wrap(err, "could not get page info")
	}
	if pageInfo.URL == "" || pageInfo.URL == "about:blank" {
		return nil, ErrEmptyPage
	}

	outerHTML, err := bounded.HTML()
	if err != nil {
		return nil, errors.Wrap(err, "could not get html content")
	}

	state := &types.PageState{
		URL:              pageInfo.URL,
		DOM:              outerHTML,
		NavigationAction: action,
		Title:            pageInfo.Title,
	}
	if action != nil {
		state.Depth = action.Depth + 1
	}
	strippedDOM, err := getStrippedDOM(outerHTML)
	if err != nil {
		return nil, errors.Wrap(err, "could not get stripped dom")
	}
	state.StrippedDOM = strippedDOM

	// Get sha256 hash of the stripped dom
	state.UniqueID = sha256Hash(strippedDOM)
	state.SimHash = simhash.Fingerprint(strings.NewReader(strippedDOM), 3)

	return state, nil
}

func sha256Hash(item string) string {
	hasher := sha256.New()
	hasher.Write([]byte(item))
	hashItem := hex.EncodeToString(hasher.Sum(nil))
	return hashItem
}

// applyNavigationStateIdentity keeps the aggressively normalized DOM useful
// for similarity while preventing distinct SPA interaction states from
// collapsing into one graph vertex. URL fragments and the semantic inventory
// of currently visible controls are stable enough for restoration, while
// generated IDs/classes/locators are deliberately excluded.
func applyNavigationStateIdentity(state *types.PageState, navigations []*types.Action) {
	if state == nil {
		return
	}
	keys := make([]string, 0, len(navigations))
	seen := make(map[string]struct{}, len(navigations))
	for _, action := range navigations {
		key := semanticActionStateKey(action)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state.ActionSignature = sha256Hash(strings.Join(keys, "\n"))
	state.UniqueID = sha256Hash(
		"url:" + state.URL + "\n" +
			"dom:" + state.StrippedDOM + "\n" +
			"actions:" + state.ActionSignature,
	)
}

func semanticActionStateKey(action *types.Action) string {
	if action == nil {
		return ""
	}
	if action.Element != nil {
		element := action.Element
		if !element.Visible || element.Disabled {
			return ""
		}
		parts := []string{
			string(action.Type),
			strings.ToUpper(strings.TrimSpace(element.TagName)),
		}
		if element.PointerEventsNone {
			parts = append(parts, "pointer-events:none")
		}
		for _, key := range []string{
			"name", "type", "href", "role", "title", "aria-label",
			"aria-labelledby", "data-testid", "data-test", "data-cy",
		} {
			if value := normalizeActionIdentityText(element.Attributes[key]); value != "" {
				parts = append(parts, key+":"+value)
			}
		}
		if text := normalizeActionIdentityText(element.TextContent); text != "" {
			if len(text) > 200 {
				text = text[:200]
			}
			parts = append(parts, "text:"+text)
		}
		return strings.Join(parts, "|")
	}
	if action.Form != nil {
		if action.Form.Hidden {
			return ""
		}
		return strings.Join([]string{
			string(action.Type),
			"form",
			normalizeActionIdentityText(action.Form.Action),
			normalizeActionIdentityText(action.Form.Method),
		}, "|")
	}
	// Direct URL loads are already globally deduplicated and do not represent
	// whether a menu/dialog is open, so they intentionally do not affect the
	// interactive state identity.
	return ""
}

func normalizeActionIdentityText(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func getStrippedDOM(contents string) (string, error) {
	normalized, err := domNormalizer.Apply(contents)
	if err != nil {
		return "", errors.Wrap(err, "could not normalize dom")
	}
	return normalized, nil
}

var ErrNoNavigationPossible = errors.New("no navigation possible")
var ErrOriginStateUnavailable = errors.New("origin state unavailable")

// navigateBackToStateOrigin implements the logic to navigate back to the state origin
//
// It implements different logics as an optimization to decide
// how to navigate back.
//
//  1. If the action has an element, check if the element is visible on the current page
//     If the element is visible, directly use that to navigate.
//
//  2. If we have browser history, and the page is in the history which was the origin
//     of the action, then we can directly use the browser history to navigate back.
//
// 3. If all else fails, we have the shortest path navigation.
func (c *Crawler) navigateBackToStateOrigin(action *types.Action, page *browser.BrowserPage, currentPageHash string) (string, error) {
	c.logger.Debug("Found action with different origin id",
		slog.String("action_origin_id", action.OriginID),
		slog.String("current_page_hash", currentPageHash),
	)

	// Get vertex from the graph
	originPageState, err := c.crawlGraph.GetPageState(action.OriginID)
	if err != nil {
		c.logger.Debug("Failed to get origin page state", slog.String("error", err.Error()))
		return "", fmt.Errorf("%w: %v", ErrOriginStateUnavailable, err)
	}

	// Prefer browser history because it preserves server and browser state while
	// still returning to the exact branch origin. Merely finding the target
	// element in the current DOM is not sufficient: persistent navigation bars
	// often contain the same control across unrelated SPA states.
	newPageHash, err := c.tryBrowserHistoryNavigation(page, originPageState, action)
	if err != nil {
		c.logger.Debug("Failed to navigate back using browser history", slog.String("error", err.Error()))
	}
	if newPageHash != "" {
		return newPageHash, nil
	}

	// Root SPA states are commonly addressable by their fragment URL. Reloading
	// that URL gives every sibling action an isolated branch and avoids stale
	// overlays, menus and component state left by the previous click.
	newPageHash, err = c.tryDirectURLNavigation(page, originPageState, action)
	if err != nil {
		c.logger.Debug("Failed to restore origin page directly", slog.String("error", err.Error()))
	}
	if newPageHash != "" {
		return newPageHash, nil
	}

	// Finally try Shortest path walking from root.
	newPageHash, err = c.tryShortestPathNavigation(action, page, currentPageHash)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOriginStateUnavailable, err)
	}
	if newPageHash == "" {
		return "", fmt.Errorf("%w: %v", ErrOriginStateUnavailable, ErrNoNavigationPossible)
	}
	return newPageHash, nil
}

func (c *Crawler) tryDirectURLNavigation(page *browser.BrowserPage, originPageState *types.PageState, action *types.Action) (string, error) {
	if originPageState == nil || originPageState.URL == "" || originPageState.URL == "about:blank" {
		return "", nil
	}
	if originPageState.Depth > 1 {
		parentState, parentErr := c.crawlGraph.GetPageState(originPageState.OriginID)
		if parentErr == nil && parentState.URL == originPageState.URL {
			// A nested interaction state (for example an open menu) cannot be
			// recreated by loading the route that merely contains it. Let the
			// graph replay its recorded click path instead.
			return "", nil
		}
	}
	pTimeout := page.Timeout(c.options.PageMaxTimeout)
	pageInfo, infoErr := pTimeout.Info()
	if infoErr == nil && pageInfo.URL == originPageState.URL {
		// Navigating a SPA to its current fragment is usually a no-op and leaves
		// menus/dialogs opened by the previous sibling action in place. A reload
		// recreates the recorded route state while preserving browser auth.
		if err := pTimeout.Reload(); err != nil {
			return "", err
		}
	} else if err := pTimeout.Navigate(originPageState.URL); err != nil {
		return "", err
	}
	if err := page.WaitPageLoadHeurisitics(); err != nil {
		return "", err
	}

	newPageHash, pageState, err := c.isCorrectNavigation(page, action)
	if err == nil {
		return newPageHash, nil
	}
	// Dynamic timestamps, telemetry attributes and rotating widgets can make an
	// otherwise restored SPA state hash differently.
	if pageState == nil || !restoredRouteCompatible(originPageState.URL, pageState.URL) {
		return "", err
	}
	// Reaching the exact recorded URL through a real navigation/reload means
	// the route origin itself was restored, even when asynchronous widgets make
	// its action signature differ. Let the normal action resolver reject a
	// vanished target; that is a stale action, not an irrecoverable state.
	return originPageState.UniqueID, nil
}

// restoredRouteCompatible accepts canonical state that an application appends
// while restoring a route, but never permits a changed route or the loss/change
// of an original parameter. It handles both normal and fragment-router query
// strings (for example #/dashboard?project=1).
func restoredRouteCompatible(recordedRaw, actualRaw string) bool {
	recorded, recordedErr := url.Parse(recordedRaw)
	actual, actualErr := url.Parse(actualRaw)
	if recordedErr != nil || actualErr != nil {
		return false
	}
	if !strings.EqualFold(recorded.Scheme, actual.Scheme) ||
		!strings.EqualFold(recorded.Host, actual.Host) ||
		recorded.EscapedPath() != actual.EscapedPath() ||
		!queryValuesSubset(recorded.Query(), actual.Query()) {
		return false
	}

	recordedFragment, recordedFragmentErr := url.Parse(recorded.Fragment)
	actualFragment, actualFragmentErr := url.Parse(actual.Fragment)
	if recordedFragmentErr != nil || actualFragmentErr != nil {
		return recorded.Fragment == actual.Fragment
	}
	return recordedFragment.EscapedPath() == actualFragment.EscapedPath() &&
		queryValuesSubset(recordedFragment.Query(), actualFragment.Query())
}

func queryValuesSubset(recorded, actual url.Values) bool {
	for key, recordedValues := range recorded {
		actualValues, exists := actual[key]
		if !exists || len(recordedValues) > len(actualValues) {
			return false
		}
		counts := make(map[string]int, len(actualValues))
		for _, value := range actualValues {
			counts[value]++
		}
		for _, value := range recordedValues {
			counts[value]--
			if counts[value] < 0 {
				return false
			}
		}
	}
	return true
}

func (c *Crawler) tryElementNavigation(page *browser.BrowserPage, action *types.Action, currentPageHash string) (string, error) {
	element, htmlElement, err := resolveActionElement(page, action.Element, c.options.PageMaxTimeout)
	if err != nil {
		return "", err
	}
	visible, err := element.Visible()
	if err != nil {
		return "", err
	}
	if !visible {
		return "", nil
	}

	// Also ensure its interactable
	interactable, err := element.Interactable()
	if err != nil || interactable == nil {
		return "", nil
	}

	// Ensure its the same element with stronger identity matching
	if isElementMatch(htmlElement, action.Element) {
		c.logger.Debug("Found target element on current page, proceeding without navigation")
		// FIXME: Return the origin element ID so that the graph shows
		// correctly the fastest way to reach the state.
		return action.OriginID, nil
	}
	return "", nil
}

// isElementMatch rejects locator drift before any click. Dynamic IDs are useful
// when equal but an ID mismatch alone is not terminal because component
// frameworks often regenerate them after a route reload.
func isElementMatch(current, target *types.HTMLElement) bool {
	if current == nil || target == nil {
		return false
	}
	if current.TagName != "" && target.TagName != "" && !strings.EqualFold(current.TagName, target.TagName) {
		return false
	}
	// Identical IDs are strong evidence, but still verify any semantic identity
	// captured with the action: SPAs can reuse one node while changing its role.
	matchCount := 0
	if current.ID != "" && target.ID != "" && current.ID == target.ID {
		matchCount += 2
	}

	if current.Classes != "" && target.Classes != "" && sameClassSet(current.Classes, target.Classes) {
		matchCount++
	}
	currentText := strings.Join(strings.Fields(current.TextContent), " ")
	targetText := strings.Join(strings.Fields(target.TextContent), " ")
	if targetText != "" {
		if currentText != targetText {
			return false
		}
		matchCount++
	}
	for _, key := range []string{"name", "type", "href", "role", "title", "aria-label", "aria-labelledby", "data-testid", "data-test", "data-cy"} {
		targetValue := strings.TrimSpace(target.Attributes[key])
		currentValue := strings.TrimSpace(current.Attributes[key])
		if targetValue == "" {
			continue
		}
		if targetValue != currentValue {
			return false
		}
		matchCount++
	}
	return matchCount > 0
}

func sameClassSet(first string, second string) bool {
	firstFields := strings.Fields(first)
	secondFields := strings.Fields(second)
	if len(firstFields) != len(secondFields) {
		return false
	}
	counts := make(map[string]int, len(firstFields))
	for _, value := range firstFields {
		counts[value]++
	}
	for _, value := range secondFields {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func (c *Crawler) tryBrowserHistoryNavigation(page *browser.BrowserPage, originPageState *types.PageState, action *types.Action) (string, error) {
	canNavigateBack, stepsBack, err := c.isBackNavigationPossible(page, originPageState)
	if err != nil {
		return "", err
	}
	if !canNavigateBack {
		return "", nil
	}

	c.logger.Debug("Navigating back using browser history", slog.Int("steps_back", stepsBack))

	var navigatedSuccessfully bool
	for i := 0; i < stepsBack; i++ {
		err := runWithNavigateBackHook(c.options.Hooks, page, page.NavigateBack)
		if err != nil {
			return "", err
		}
		navigatedSuccessfully = true
	}

	if !navigatedSuccessfully {
		return "", nil
	}

	if err := page.WaitPageLoadHeurisitics(); err != nil {
		c.logger.Debug("Failed to wait for page load after navigating back using browser history", slog.String("error", err.Error()))
	}
	newPageHash, pageState, err := c.isCorrectNavigation(page, action)
	if c.diagnostics != nil && pageState != nil {
		if err := c.diagnostics.LogPageState(pageState, diagnostics.PreActionPageState); err != nil {
			return "", err
		}
	}
	if err != nil {
		return "", err
	}
	return newPageHash, nil
}

func (c *Crawler) isBackNavigationPossible(page *browser.BrowserPage, originPage *types.PageState) (bool, int, error) {
	history, err := page.GetNavigationHistory()
	if err != nil {
		return false, 0, err
	}
	if len(history.Entries) == 0 {
		return false, 0, nil
	}

	currentIndex := history.CurrentIndex
	for i, entry := range history.Entries {
		if entry.URL == originPage.URL && originPage.Title == entry.Title {
			stepsBack := currentIndex - i
			return true, stepsBack, nil
		}
	}
	return false, 0, nil
}

func (c *Crawler) tryShortestPathNavigation(action *types.Action, page *browser.BrowserPage, currentPageHash string) (string, error) {
	c.logger.Debug("Trying Shortest path to navigate back to origin page", slog.String("action_origin_id", action.OriginID), slog.String("current_page_hash", currentPageHash))

	actions, err := c.crawlGraph.ShortestPath(currentPageHash, action.OriginID)
	if err != nil {
		if errors.Is(err, graphlib.ErrTargetNotReachable) {
			c.logger.Debug("Target not reachable, reaching from blank state",
				slog.String("action_origin_id", action.OriginID),
			)

			actions, err = c.crawlGraph.ShortestPath(emptyPageHash, action.OriginID)
			if err != nil {
				return "", errors.Wrap(err, "could not find path to origin page")
			}
		} else {
			return "", errors.Wrap(err, "failed to find shortest path")
		}
	}
	c.logger.Debug("Found actions to traverse",
		slog.Any("actions", actions),
	)
	for _, action := range actions {
		if err := c.executeCrawlStateAction(action, page); err != nil {
			return "", err
		}
	}
	newPageHash, pageState, err := c.isCorrectNavigation(page, action)
	if c.diagnostics != nil && pageState != nil {
		if err := c.diagnostics.LogPageState(pageState, diagnostics.PreActionPageState); err != nil {
			return "", err
		}
	}
	if err != nil {
		return "", err
	}
	return newPageHash, nil
}

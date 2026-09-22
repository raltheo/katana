package browser

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
)

const (
	// buttonsCSSSelector is the css selector for all buttons
	buttonsCSSSelector = "button, input[type='button'], input[type='submit'], [role='button'], [role='link'], [aria-haspopup], [onclick], summary, [tabindex]:not([tabindex='-1'])"
	// linksCSSSelector is the css selector for all anchor tags
	linksCSSSelector = "a"
)

// isElementDisabled checks if a button element is disabled
func isElementDisabled(element *types.HTMLElement) bool {
	if element.Disabled {
		return true
	}
	if element.Attributes == nil {
		return false
	}

	// Standard HTML disabled attribute
	if _, disabled := element.Attributes["disabled"]; disabled {
		return true
	}

	// Tailwind or framework class-based detection
	if classAttr, ok := element.Attributes["class"]; ok {
		classList := strings.Fields(classAttr)
		for _, class := range classList {
			if class == "cursor-not-allowed" {
				return true
			}
		}
	}

	// Optionally support ARIA disabled
	if aria, ok := element.Attributes["aria-disabled"]; ok && (aria == "true" || aria == "1") {
		return true
	}

	return false
}

// isLikelyClickable rejects focus-only nodes. A tabindex makes an element
// keyboard-focusable, but does not imply that clicking it can navigate or
// reveal content (tooltip labels are a common example). Native controls,
// explicit interactive semantics, inline handlers and pointer cursors remain
// eligible. Registered event listeners are collected in a separate pass.
func isLikelyClickable(element *types.HTMLElement) bool {
	if element == nil {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(element.TagName)) {
	case "A", "BUTTON", "INPUT", "SUMMARY":
		return true
	}
	attributes := element.Attributes
	role := strings.ToLower(strings.TrimSpace(attributes["role"]))
	switch role {
	case "button", "link":
		return true
	}
	if _, ok := attributes["aria-haspopup"]; ok {
		return true
	}
	if strings.TrimSpace(attributes["onclick"]) != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(element.Cursor), "pointer")
}

// FindNavigation attempts to find more navigations on the page which could
// be done to find more links and pages.
//
// This includes the following -
//  1. Forms
//  2. Buttons
//  3. Links
//  4. Elements with event listeners
//
// The navigations found are unique across the page. The caller
// needs to ensure they are unique globally before doing further actions with details.
func (b *BrowserPage) FindNavigations() ([]*types.Action, error) {
	unique := make(map[string]struct{})

	navigations := make([]*types.Action, 0)

	forms, err := b.GetAllForms()
	if err != nil {
		return nil, errors.Wrap(err, "could not get forms")
	}
	for _, form := range forms {
		for _, element := range form.Elements {
			if element.TagName != "BUTTON" {
				continue
			}
			// TODO: Check if this button is already in the unique map
			// and if so remove it
			unique[element.Hash()] = struct{}{}
		}
		hash := form.Hash()
		if _, found := unique[hash]; found {
			continue
		}
		unique[hash] = struct{}{}

		navigations = append(navigations, &types.Action{
			Type: types.ActionTypeFillForm,
			Form: form,
		})
	}

	buttons, err := b.GetAllElements(buttonsCSSSelector)
	if err != nil {
		return nil, errors.Wrap(err, "could not get buttons")
	}
	for _, button := range buttons {
		if !isLikelyClickable(button) {
			continue
		}
		hash := button.Hash()
		button.MD5Hash = hash

		if _, found := unique[hash]; found {
			continue
		}
		unique[hash] = struct{}{}
		navigations = append(navigations, &types.Action{
			Type:    types.ActionTypeLeftClick,
			Element: button,
		})
	}

	scopeValidator := b.launcher.ScopeValidator()
	links, err := b.GetAllElements(linksCSSSelector)
	if err != nil {
		return nil, errors.Wrap(err, "could not get links")
	}
	info, err := b.Info()
	if err != nil {
		return nil, errors.Wrap(err, "could not get page info")
	}
	for _, link := range links {
		href := link.Attributes["href"]
		if href == "" {
			continue
		}

		baseURL := info.URL
		if link.DocumentURL != "" {
			baseURL = link.DocumentURL
		}
		resolvedHref, err := resolveURL(baseURL, href)
		if err != nil {
			continue
		}

		u, err := url.Parse(resolvedHref)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if !scopeValidator(resolvedHref) {
			continue
		}

		hash := link.Hash()
		link.MD5Hash = hash

		if _, found := unique[hash]; found {
			continue
		}
		unique[hash] = struct{}{}
		navigations = append(navigations, &types.Action{
			Type:    types.ActionTypeLeftClick,
			Element: link,
		})
	}

	eventListeners, err := b.GetEventListeners()
	if err != nil {
		return nil, errors.Wrap(err, "could not get event listeners")
	}
	for _, listener := range eventListeners {
		if _, found := relevantEventListeners[listener.Type]; !found {
			continue
		}
		if listener.Element == nil {
			continue
		}
		hash := listener.Element.Hash()
		listener.Element.MD5Hash = hash
		if _, found := unique[hash]; found {
			continue
		}
		unique[hash] = struct{}{}
		navigations = append(navigations, types.ActionFromEventListener(listener))
	}

	navLinks, err := b.GetNavigatedLinks()
	if err == nil {
		for _, link := range navLinks {
			if link.URL == "" {
				continue
			}
			resolved, err := resolveURL(info.URL, link.URL)
			if err != nil {
				continue
			}
			if _, found := unique[resolved]; found {
				continue
			}
			unique[resolved] = struct{}{}
			navigations = append(navigations, &types.Action{
				Type:  types.ActionTypeLoadURL,
				Input: resolved,
			})
		}
	}

	return navigations, nil
}

func (b *BrowserPage) GetAllElements(selector string) ([]*types.HTMLElement, error) {
	objects, err := b.Eval(`() => window.getAllElements(` + strconv.Quote(selector) + `)`)
	if err != nil {
		return nil, err
	}

	elements := make([]*types.HTMLElement, 0)
	if err := objects.Value.Unmarshal(&elements); err != nil {
		return nil, err
	}
	return elements, nil
}

// GetAllElementsWithTimeout bounds deep Shadow DOM/iframe enumeration. A
// detached or busy external Chrome target must not turn a stale action lookup
// into a full page timeout for every queued control.
func (b *BrowserPage) GetAllElementsWithTimeout(selector string, timeout time.Duration) ([]*types.HTMLElement, error) {
	copy := *b
	copy.Page = b.Timeout(timeout)
	return copy.GetAllElements(selector)
}

func (b *BrowserPage) GetElementFromXpath(xpath string) (*types.HTMLElement, error) {
	object, err := b.Eval(`() => window.getElementFromXPath(` + strconv.Quote(xpath) + `)`)
	if err != nil {
		return nil, err
	}

	element := &types.HTMLElement{}
	if err := object.Value.Unmarshal(element); err != nil {
		return nil, err
	}
	return element, nil
}

// GetElement resolves an element using a boundary-aware locator when one is
// available, with XPath retained as a compatibility fallback for normal DOM.
func (b *BrowserPage) GetElement(element *types.HTMLElement) (*rod.Element, error) {
	if element != nil && len(element.DeepLocator) > 0 {
		currentPage := b.Page
		var currentRoot *rod.Element
		for _, step := range element.DeepLocator {
			var current *rod.Element
			var err error
			if currentRoot != nil {
				current, err = currentRoot.Element(step.Selector)
			} else {
				current, err = currentPage.Element(step.Selector)
			}
			if err != nil {
				return nil, err
			}
			switch step.Type {
			case "shadow":
				currentRoot, err = current.ShadowRoot()
				if err != nil {
					return nil, err
				}
			case "iframe":
				currentPage, err = current.Frame()
				if err != nil {
					return nil, err
				}
				currentRoot = nil
			case "element":
				return current, nil
			default:
				return nil, errors.Errorf("unsupported locator step %q", step.Type)
			}
		}
		return nil, errors.New("deep locator did not identify an element")
	}
	if element == nil || element.XPath == "" {
		return nil, errors.New("element has no usable locator")
	}
	return b.ElementX(element.XPath)
}

// GetElementWithTimeout resolves an element with a bounded Rod query context.
func (b *BrowserPage) GetElementWithTimeout(element *types.HTMLElement, timeout time.Duration) (*rod.Element, error) {
	copy := *b
	copy.Page = b.Timeout(timeout)
	return copy.GetElement(element)
}

// GetElementData resolves and serializes the current element so callers can
// verify that a stored action still targets the same node.
func (b *BrowserPage) GetElementData(element *types.HTMLElement) (*types.HTMLElement, error) {
	if element != nil && len(element.DeepLocator) > 0 {
		resolved, err := b.GetElement(element)
		if err != nil {
			return nil, err
		}
		return b.GetResolvedElementData(resolved)
	}
	if element == nil || element.XPath == "" {
		return nil, errors.New("element has no usable locator")
	}
	return b.GetElementFromXpath(element.XPath)
}

// GetResolvedElementData serializes an element that has already been resolved.
// Keeping resolution and identity verification on the same DOM node prevents
// a dynamic selector from being evaluated twice across a React re-render.
func (b *BrowserPage) GetResolvedElementData(element *rod.Element) (*types.HTMLElement, error) {
	if element == nil {
		return nil, errors.New("resolved element is nil")
	}
	object, err := element.Eval(`() => window._elementDataFromElement(this)`)
	if err != nil {
		return nil, err
	}
	current := &types.HTMLElement{}
	if err := object.Value.Unmarshal(current); err != nil {
		return nil, err
	}
	return current, nil
}

func (b *BrowserPage) GetAllForms() ([]*types.HTMLForm, error) {
	objects, err := b.Eval(`() => window.getAllForms()`)
	if err != nil {
		return nil, err
	}

	elements := make([]*types.HTMLForm, 0)
	if err := objects.Value.Unmarshal(&elements); err != nil {
		return nil, err
	}
	return elements, nil
}

// GetEventListeners returns all event listeners on the page
func (b *BrowserPage) GetEventListeners() ([]*types.EventListener, error) {
	listeners := make([]*types.EventListener, 0)

	eventlisteners, err := b.Eval(`() => window.getAllRegisteredEventListeners()`)
	if err == nil {
		_ = eventlisteners.Value.Unmarshal(&listeners)
	}

	// Also get inline event listeners
	var inlineEventListeners []struct {
		Element   *types.HTMLElement `json:"element"`
		Listeners []struct {
			Type     string `json:"type"`
			Listener string `json:"listener"`
		} `json:"listeners"`
	}
	inlineListeners, err := b.Eval(`() => window.getAllElementsWithEventListeners()`)
	if err != nil {
		return nil, err
	}
	if err := inlineListeners.Value.Unmarshal(&inlineEventListeners); err != nil {
		return nil, err
	}

	for _, inlineListener := range inlineEventListeners {
		for _, listener := range inlineListener.Listeners {
			listenerType := strings.TrimPrefix(listener.Type, "on")
			listeners = append(listeners, &types.EventListener{
				Type:     listenerType,
				Listener: listener.Listener,
				Element:  inlineListener.Element,
			})
		}
	}
	return listeners, nil
}

// NavigatedLink is a link navigated collected from one of the
// navigation hooks.
type NavigatedLink struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

// GetNavigatedLinks returns all navigated links on the page
func (b *BrowserPage) GetNavigatedLinks() ([]*NavigatedLink, error) {
	navigatedLinks, err := b.Eval(`() => window.__navigatedLinks`)
	if err != nil {
		return nil, err
	}

	listeners := make([]*NavigatedLink, 0)
	if err := navigatedLinks.Value.Unmarshal(&listeners); err != nil {
		return nil, err
	}
	return listeners, nil
}

// Define the map to hold event types
var relevantEventListeners = map[string]struct{}{
	// Focus and Blur events
	"focusin":  {},
	"focus":    {},
	"blur":     {},
	"focusout": {},

	// Click and Mouse events
	"click":       {},
	"auxclick":    {},
	"mousedown":   {},
	"mouseup":     {},
	"dblclick":    {},
	"mouseover":   {},
	"mouseenter":  {},
	"mouseleave":  {},
	"mouseout":    {},
	"wheel":       {},
	"contextmenu": {},

	// Key events
	"keydown":  {},
	"keypress": {},
	"keyup":    {},

	// Form events
	"submit": {},
	"input":  {},
	"change": {},
}

// resolveURL resolves a potentially relative URL against a base URL
func resolveURL(baseURLStr, href string) (string, error) {
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return "", err
	}

	resolvedURL, err := baseURL.Parse(href)
	if err != nil {
		return "", err
	}
	return resolvedURL.String(), nil
}

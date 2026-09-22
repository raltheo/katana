package crawler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adrianbrad/queue"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/stretchr/testify/require"
)

func TestDeniedActionUsesNarrowSafetyVocabulary(t *testing.T) {
	for _, value := range []string{
		"Logout", "log out", "Sign out", "sign-out", "signout",
		"signOut", "Delete", "deleteProject", "Remove", "Pay",
		"/account/logout", "?action=delete",
	} {
		require.True(t, containsDeniedAction(value), "expected denied term in %q", value)
	}
	for _, value := range []string{
		"disconnect", "exit", "terminate", "sign in", "payment",
		"payload", "repayment", "display", "removeable",
	} {
		require.False(t, containsDeniedAction(value), "unexpected denied term in %q", value)
	}
}

func TestElementIdentityFailsClosedOnLocatorDrift(t *testing.T) {
	target := &types.HTMLElement{
		TagName:     "SPAN",
		ID:          "radix-_r_old_",
		Classes:     "tooltip trigger",
		TextContent: "Google Analytics",
		Attributes:  map[string]string{"data-testid": "feature-tooltip-trigger"},
	}
	restored := &types.HTMLElement{
		TagName:     "SPAN",
		ID:          "radix-_r_new_",
		Classes:     "trigger tooltip",
		TextContent: "  Google   Analytics ",
		Attributes:  map[string]string{"data-testid": "feature-tooltip-trigger"},
	}
	wrongTag := *restored
	wrongTag.TagName = "A"
	wrongText := *restored
	wrongText.TextContent = "Jira"
	wrongAttribute := *restored
	wrongAttribute.Attributes = map[string]string{"data-testid": "different-control"}

	require.True(t, isElementMatch(restored, target), "generated IDs and class order may change")
	require.False(t, isElementMatch(&wrongTag, target), "a stale selector must never change element type")
	require.False(t, isElementMatch(&wrongText, target), "a stale selector must never change control text")
	require.False(t, isElementMatch(&wrongAttribute, target), "stable identity attributes must agree")
}

func TestActionDocumentIdentityIncludesSPARoute(t *testing.T) {
	require.True(t, sameActionDocument(
		"https://example.test/#/dashboard?project=1",
		"https://EXAMPLE.test/#/dashboard?project=1",
	))
	require.False(t, sameActionDocument(
		"https://example.test/#/dashboard?project=1",
		"https://example.test/#/integrations",
	))
}

func TestEnqueueNavigationsDefersHiddenAndKeepsDistinctControls(t *testing.T) {
	crawler := &Crawler{
		logger:        slog.Default(),
		crawlQueue:    queue.NewLinked([]*types.Action{}),
		uniqueActions: make(map[string]struct{}),
		options:       Options{MaxActionsPerState: 10},
	}
	state := &types.PageState{UniqueID: "state-a", Depth: 1}
	hidden := &types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TagName: "BUTTON", TextContent: "Hidden menu", Visible: false,
			DeepLocator: []types.ElementLocatorStep{{Type: "element", Selector: "#hidden"}},
		},
	}
	first := &types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TagName: "BUTTON", Classes: "item", TextContent: "First", Visible: true,
			DeepLocator: []types.ElementLocatorStep{{Type: "element", Selector: "button:nth-of-type(1)"}},
		},
	}
	second := &types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TagName: "BUTTON", Classes: "item", TextContent: "Second", Visible: true,
			DeepLocator: []types.ElementLocatorStep{{Type: "element", Selector: "button:nth-of-type(2)"}},
		},
	}
	denied := &types.Action{
		Type:    types.ActionTypeLeftClick,
		Element: &types.HTMLElement{TagName: "BUTTON", TextContent: "Delete project", Visible: true},
	}

	require.NoError(t, crawler.enqueueNavigations(state, []*types.Action{hidden, first, second, denied}))
	require.Equal(t, 2, crawler.crawlQueue.Size())

	// A deferred control must not be poisoned in the global unique set. It can
	// be queued later when a parent action makes it visible.
	hidden.Element.Visible = true
	require.NoError(t, crawler.enqueueNavigations(state, []*types.Action{hidden}))
	require.Equal(t, 3, crawler.crawlQueue.Size())
}

func TestEnqueueNavigationsHonorsPerStateLimit(t *testing.T) {
	crawler := &Crawler{
		logger:        slog.Default(),
		crawlQueue:    queue.NewLinked([]*types.Action{}),
		uniqueActions: make(map[string]struct{}),
		options:       Options{MaxActionsPerState: 1},
	}
	state := &types.PageState{UniqueID: "state-a", Depth: 1}
	actions := []*types.Action{
		{Type: types.ActionTypeLeftClick, Element: &types.HTMLElement{TagName: "BUTTON", TextContent: "First", Visible: true}},
		{Type: types.ActionTypeLeftClick, Element: &types.HTMLElement{TagName: "BUTTON", TextContent: "Second", Visible: true}},
	}
	require.NoError(t, crawler.enqueueNavigations(state, actions))
	require.Equal(t, 1, crawler.crawlQueue.Size())
}

func TestPerStateLimitWritesOneCompactTruncationEvent(t *testing.T) {
	journal, err := newActionJournal(filepath.Join(t.TempDir(), "actions.jsonl"))
	require.NoError(t, err)
	crawler := &Crawler{
		logger:        slog.Default(),
		crawlQueue:    queue.NewLinked([]*types.Action{}),
		uniqueActions: make(map[string]struct{}),
		actionJournal: journal,
		options:       Options{MaxActionsPerState: 1},
	}
	state := &types.PageState{UniqueID: "state-a", Depth: 1}
	actions := make([]*types.Action, 100)
	for index := range actions {
		actions[index] = &types.Action{
			Type: types.ActionTypeLeftClick,
			Element: &types.HTMLElement{
				TagName: "BUTTON", TextContent: fmt.Sprintf("Action %d", index), Visible: true,
			},
		}
	}
	require.NoError(t, crawler.enqueueNavigations(state, actions))
	require.NoError(t, journal.Close())

	file, err := os.Open(filepath.Join(journal.baseDir, "actions.jsonl"))
	require.NoError(t, err)
	defer file.Close()
	var events []actionJournalEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event actionJournalEvent
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		events = append(events, event)
	}
	require.NoError(t, scanner.Err())
	require.Len(t, events, 3)
	require.Equal(t, "queued", events[0].Result)
	require.Equal(t, "per-state action limit reached", events[1].Reason)
	require.Equal(t, 2, events[2].InventoryVersion)
	require.Equal(t, 100, events[2].CandidateActions)
	require.Equal(t, 99, events[2].OmittedActions)
	require.True(t, events[2].InventoryTruncated)
}

func TestEnqueueNavigationsDefersPointerBlockedControlsAndLoadsSafeLinks(t *testing.T) {
	crawler := &Crawler{
		logger:        slog.Default(),
		crawlQueue:    queue.NewLinked([]*types.Action{}),
		uniqueActions: make(map[string]struct{}),
		options: Options{ScopeValidator: func(rawURL string) bool {
			return strings.HasPrefix(rawURL, "https://example.test/")
		}},
	}
	state := &types.PageState{UniqueID: "state-a", Depth: 1}
	blockedButton := &types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TagName: "BUTTON", Visible: true, PointerEventsNone: true,
			TextContent: "Collapsed action",
		},
	}
	blockedLink := &types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TagName: "A", Visible: true, PointerEventsNone: true,
			TextContent: "Dashboard", DocumentURL: "https://example.test/#/home",
			Attributes: map[string]string{"href": "#/dashboard"},
		},
	}

	require.NoError(t, crawler.enqueueNavigations(state, []*types.Action{blockedButton, blockedLink}))
	require.Equal(t, 1, crawler.crawlQueue.Size())
	queued, err := crawler.crawlQueue.Get()
	require.NoError(t, err)
	require.Equal(t, types.ActionTypeLoadURL, queued.Type)
	require.Equal(t, "https://example.test/#/dashboard", queued.Input)
	require.NotContains(t, crawler.uniqueActions, blockedButton.Hash())
}

func TestLinkFallbackCanonicalizesAbsoluteHashRoute(t *testing.T) {
	crawler := &Crawler{options: Options{ScopeValidator: func(string) bool { return true }}}
	fallback := crawler.linkFallbackAction(&types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TagName:     "A",
			DocumentURL: "https://example.test/#/home",
			Attributes:  map[string]string{"href": "https://example.test#/dashboard"},
		},
	})
	require.NotNil(t, fallback)
	require.Equal(t, "https://example.test/#/dashboard", fallback.Input)
}

func TestDeniedActionCoversURLsElementsAndForms(t *testing.T) {
	require.True(t, isDeniedAction(&types.Action{
		Type:  types.ActionTypeLoadURL,
		Input: "https://example.test/session/logout",
	}))
	require.True(t, isDeniedAction(&types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			Attributes: map[string]string{"data-testid": "remove-member"},
		},
	}))
	require.True(t, isDeniedAction(&types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			Attributes: map[string]string{"aria-label": "Delete project"},
		},
	}))
	require.True(t, isDeniedAction(&types.Action{
		Type: types.ActionTypeFillForm,
		Form: &types.HTMLForm{
			Action: "/billing/pay",
		},
	}))
	require.False(t, isDeniedAction(&types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TextContent: "Open payment settings",
			Attributes:  map[string]string{"href": "/settings/payment"},
		},
	}))
	require.False(t, isDeniedAction(&types.Action{
		Type: types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TextContent: "Open menu",
			OuterHTML:   `<button onclick="panel.remove()">Open menu</button>`,
			Attributes:  map[string]string{"onclick": "panel.remove()"},
		},
	}))
}

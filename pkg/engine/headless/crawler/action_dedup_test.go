package crawler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/katana/pkg/engine/headless/graph"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/stretchr/testify/require"
)

func TestLoadActionDedupKeys(t *testing.T) {
	keyA := "a8f1f245a0543a177b84905c0c566b07f5e25d978663025730a66cfcb7264c18"
	keyB := "19e41646102d4f763b633b23a07a1967006ca7c812671b32d54868d595a277b8"
	path := filepath.Join(t.TempDir(), "coverage.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(
		`{"coverage_key":"`+keyA+`","confirmed_seeds":2}`+"\n"+keyB+"\n",
	), 0600))

	keys, err := loadActionDedupKeys(path)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Contains(t, keys, keyA)
	require.Contains(t, keys, keyB)
}

func TestSemanticActionCoverageIsExactAndOutcomeOrderStable(t *testing.T) {
	crawlGraph := graph.NewCrawlGraph()
	origin := types.PageState{
		UniqueID:        "origin-state",
		URL:             "https://example.test/#/catalog?project=42",
		StrippedDOM:     "<main>catalog</main>",
		ActionSignature: "visible-controls",
	}
	require.NoError(t, crawlGraph.AddPageState(origin))
	after := types.PageState{
		UniqueID:        "after-state",
		URL:             "https://example.test/#/details?project=42",
		StrippedDOM:     "<main>details</main>",
		ActionSignature: "detail-controls",
	}
	require.NoError(t, crawlGraph.AddPageState(after))

	crawler := &Crawler{crawlGraph: crawlGraph}
	action := &types.Action{
		OriginID: origin.UniqueID,
		Type:     types.ActionTypeLeftClick,
		Element: &types.HTMLElement{
			TagName:     "BUTTON",
			Visible:     true,
			TextContent: "Open integration",
			Attributes:  map[string]string{"role": "button"},
		},
	}
	key := crawler.actionCoverageKey(action)
	require.Regexp(t, actionCoverageKeyPattern, key)

	changedAction := *action
	changedElement := *action.Element
	changedElement.TextContent = "Open another integration"
	changedAction.Element = &changedElement
	require.NotEqual(t, key, crawler.actionCoverageKey(&changedAction))

	first := &actionOutcome{
		Executed:           true,
		AfterStateID:       after.UniqueID,
		AfterURL:           after.URL,
		DOMChanged:         true,
		NetworkFingerprint: sha256Hash("https://example.test/api"),
		PopupURLs:          []string{"https://example.test/b", "https://example.test/a"},
	}
	second := &actionOutcome{
		Executed:           true,
		AfterStateID:       after.UniqueID,
		AfterURL:           after.URL,
		DOMChanged:         true,
		NetworkFingerprint: sha256Hash("https://example.test/api"),
		PopupURLs:          []string{"https://example.test/a", "https://example.test/b"},
	}
	require.Equal(
		t,
		crawler.actionOutcomeFingerprint(first),
		crawler.actionOutcomeFingerprint(second),
	)
	second.NetworkFingerprint = sha256Hash("https://example.test/other-api")
	require.NotEqual(
		t,
		crawler.actionOutcomeFingerprint(first),
		crawler.actionOutcomeFingerprint(second),
	)

	uncertain := &actionOutcome{Executed: true, StateCaptureFailed: true}
	require.Empty(t, crawler.actionOutcomeFingerprint(uncertain))
}

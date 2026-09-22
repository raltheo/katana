package crawler

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/katana/pkg/engine/headless/types"
	"github.com/stretchr/testify/require"
)

func TestActionTargetFamilyCircuitBreaker(t *testing.T) {
	action := targetFamilyTestAction("menu-open", "feature-tooltip-trigger", "First")
	sibling := targetFamilyTestAction("menu-open", "feature-tooltip-trigger", "Second")
	unrelated := targetFamilyTestAction("menu-open", "navigation-button", "Dashboard")
	crawler := &Crawler{
		options:               Options{MaxFailureCount: 3, ContinueOnActionFailure: true},
		targetFamilyFailures:  make(map[string]int),
		invalidTargetFamilies: make(map[string]string),
	}

	crawler.trackActionTargetFailure(action, nil, ErrElementNotVisible)
	crawler.trackActionTargetFailure(sibling, nil, errors.Wrap(ErrActionElementAmbiguous, "resolver"))
	require.NotContains(t, crawler.invalidTargetFamilies, actionTargetFamilyKey(action))

	crawler.trackActionTargetFailure(action, nil, ErrElementNotVisible)
	require.Contains(t, crawler.invalidTargetFamilies, actionTargetFamilyKey(action))
	require.Contains(t, crawler.invalidTargetFamilies[actionTargetFamilyKey(action)], "3 consecutive")
	require.NotEqual(t, actionTargetFamilyKey(action), actionTargetFamilyKey(unrelated))
	require.NotContains(t, crawler.invalidTargetFamilies, actionTargetFamilyKey(unrelated))
}

func TestActionTargetFamilyCircuitBreakerResetsAndCanBeDisabled(t *testing.T) {
	action := targetFamilyTestAction("dialog-open", "dialog-row", "Row")
	crawler := &Crawler{
		options:               Options{MaxFailureCount: 2, ContinueOnActionFailure: true},
		targetFamilyFailures:  make(map[string]int),
		invalidTargetFamilies: make(map[string]string),
	}

	crawler.trackActionTargetFailure(action, nil, ErrElementNotVisible)
	crawler.trackActionTargetFailure(action, nil, errors.New("unrelated navigation failure"))
	crawler.trackActionTargetFailure(action, nil, ErrElementNotVisible)
	require.NotContains(t, crawler.invalidTargetFamilies, actionTargetFamilyKey(action), "a non-target failure must break the consecutive sequence")

	disabled := &Crawler{
		options:               Options{MaxFailureCount: 0, ContinueOnActionFailure: true},
		targetFamilyFailures:  make(map[string]int),
		invalidTargetFamilies: make(map[string]string),
	}
	for range 20 {
		disabled.trackActionTargetFailure(action, nil, ErrElementNotVisible)
	}
	require.Empty(t, disabled.invalidTargetFamilies)
}

func TestActionTargetFamilyUsesDedicatedThreshold(t *testing.T) {
	action := targetFamilyTestAction("menu-open", "tooltip-trigger", "First")
	crawler := &Crawler{
		options: Options{
			MaxFailureCount:      10,
			MaxStaleActionFamily: 3,
		},
		targetFamilyFailures:  make(map[string]int),
		invalidTargetFamilies: make(map[string]string),
	}

	for range 3 {
		crawler.trackActionTargetFailure(action, nil, ErrElementNotVisible)
	}
	require.Contains(t, crawler.invalidTargetFamilies, actionTargetFamilyKey(action))
}

func TestStaleActionTargetFailureClassification(t *testing.T) {
	require.True(t, isStaleActionTargetFailure(ErrElementNotVisible))
	require.True(t, isStaleActionTargetFailure(errors.Wrap(ErrActionElementAmbiguous, "resolver")))
	require.False(t, isStaleActionTargetFailure(errors.New("navigation failed")))
}

func targetFamilyTestAction(origin, testID, text string) *types.Action {
	return &types.Action{
		Type:     types.ActionTypeLeftClick,
		OriginID: origin,
		Element: &types.HTMLElement{
			TagName:     "SPAN",
			TextContent: text,
			Attributes:  map[string]string{"data-testid": testID},
		},
	}
}

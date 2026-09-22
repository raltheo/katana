package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestActionHashSeparatesStateAndElementIdentity(t *testing.T) {
	baseElement := &HTMLElement{
		TagName:     "BUTTON",
		Classes:     "menu-item primary",
		TextContent: "First dashboard",
		DeepLocator: []ElementLocatorStep{{Type: "element", Selector: "nav > button:nth-of-type(1)"}},
	}
	first := &Action{Type: ActionTypeLeftClick, OriginID: "state-a", Element: baseElement}
	same := &Action{Type: ActionTypeLeftClick, OriginID: "state-a", Element: baseElement}
	differentState := &Action{Type: ActionTypeLeftClick, OriginID: "state-b", Element: baseElement}
	differentControl := &Action{
		Type:     ActionTypeLeftClick,
		OriginID: "state-a",
		Element: &HTMLElement{
			TagName:     "BUTTON",
			Classes:     "menu-item primary",
			TextContent: "Second dashboard",
			DeepLocator: []ElementLocatorStep{{Type: "element", Selector: "nav > button:nth-of-type(2)"}},
		},
	}

	require.Equal(t, first.Hash(), same.Hash())
	require.NotEqual(t, first.Hash(), differentState.Hash())
	require.NotEqual(t, first.Hash(), differentControl.Hash())
}

func TestLoadURLActionHashIgnoresOriginState(t *testing.T) {
	first := &Action{Type: ActionTypeLoadURL, OriginID: "state-a", Input: "https://example.test/dashboard"}
	second := &Action{Type: ActionTypeLoadURL, OriginID: "state-b", Input: "https://example.test/dashboard"}
	different := &Action{Type: ActionTypeLoadURL, OriginID: "state-a", Input: "https://example.test/settings"}

	require.Equal(t, first.Hash(), second.Hash())
	require.NotEqual(t, first.Hash(), different.Hash())
}

func TestElementHashUsesAccessibleStableAttributes(t *testing.T) {
	first := &HTMLElement{
		TagName:    "BUTTON",
		Classes:    "icon-button",
		Attributes: map[string]string{"aria-label": "Open projects"},
	}
	second := &HTMLElement{
		TagName:    "BUTTON",
		Classes:    "icon-button",
		Attributes: map[string]string{"aria-label": "Open settings"},
	}
	require.NotEqual(t, first.Hash(), second.Hash())
}

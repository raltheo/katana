package runner

import (
	"testing"

	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/stretchr/testify/require"
)

func newTestOptions() *types.Options {
	return &types.Options{
		MaxDepth: 2,
		URLs:     []string{"https://example.com"},
	}
}

func TestValidatePageLoadStrategy(t *testing.T) {
	t.Run("valid strategies are accepted", func(t *testing.T) {
		for _, strategy := range []string{"heuristic", "adaptive", "load", "domcontentloaded", "networkidle", "none"} {
			opts := newTestOptions()
			opts.PageLoadStrategy = strategy
			err := validateOptions(opts)
			require.NoError(t, err, "strategy %q should be valid", strategy)
			require.Equal(t, strategy, opts.PageLoadStrategy)
		}
	})

	t.Run("empty strategy defaults to heuristic", func(t *testing.T) {
		opts := newTestOptions()
		opts.PageLoadStrategy = ""
		err := validateOptions(opts)
		require.NoError(t, err)
		require.Equal(t, "heuristic", opts.PageLoadStrategy)
	})

	t.Run("invalid strategy is rejected", func(t *testing.T) {
		opts := newTestOptions()
		opts.PageLoadStrategy = "invalid"
		err := validateOptions(opts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid page-load-strategy")
	})
}

func TestValidateHeadlessFlags(t *testing.T) {
	t.Run("headless and hybrid are mutually exclusive", func(t *testing.T) {
		opts := newTestOptions()
		opts.Headless = true
		opts.HeadlessHybrid = true
		err := validateOptions(opts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("no-sandbox without headless mode fails", func(t *testing.T) {
		opts := newTestOptions()
		opts.HeadlessNoSandbox = true
		err := validateOptions(opts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "headless")
	})

	t.Run("no-sandbox with headless mode succeeds", func(t *testing.T) {
		opts := newTestOptions()
		opts.Headless = true
		opts.HeadlessNoSandbox = true
		err := validateOptions(opts)
		require.NoError(t, err)
	})
}

func TestValidateActionRuntimeLimits(t *testing.T) {
	for _, mutate := range []func(*types.Options){
		func(options *types.Options) { options.MaxStaleActionFamily = -1 },
		func(options *types.Options) { options.MaxActionRuntime = -1 },
		func(options *types.Options) { options.MaxActionRetries = -1 },
		func(options *types.Options) { options.ActionPreflightTimeout = -1 },
		func(options *types.Options) { options.ActionSignalTimeout = -1 },
		func(options *types.Options) { options.ActionQuietPeriod = -1 },
	} {
		options := newTestOptions()
		mutate(options)
		err := validateOptions(options)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be zero or greater")
	}
}

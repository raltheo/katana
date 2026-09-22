package runner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/yaml.v3"
)

// validateOptions validates the provided options for crawler
func validateOptions(options *types.Options) error {
	if options.MaxDepth <= 0 && options.CrawlDuration.Seconds() <= 0 {
		return errkit.New("either max-depth or crawl-duration must be specified")
	}
	if len(options.URLs) == 0 && !fileutil.HasStdin() {
		return errkit.New("no inputs specified for crawler")
	}

	// Validate page load strategy
	if options.PageLoadStrategy != "" {
		validStrategies := []string{"heuristic", "adaptive", "load", "domcontentloaded", "networkidle", "none"}
		if !slices.Contains(validStrategies, options.PageLoadStrategy) {
			return errkit.New("invalid page-load-strategy: must be one of (heuristic, adaptive, load, domcontentloaded, networkidle, none)")
		}
	} else {
		// Default to heuristic
		options.PageLoadStrategy = "heuristic"
	}
	if options.ScrollStep <= 0 {
		options.ScrollStep = 700
	}
	if options.ScrollDelay < 0 {
		return errkit.New("scroll-delay must be zero or greater")
	}
	if options.MaxScrollSteps <= 0 {
		options.MaxScrollSteps = 40
	}
	if options.MaxActionDepth < 0 {
		return errkit.New("max-action-depth must be zero or greater")
	}
	if options.MaxStaleActionFamily < 0 {
		return errkit.New("max-stale-action-family must be zero or greater")
	}
	if options.MaxActionsPerState < 0 {
		return errkit.New("max-actions-per-state must be zero or greater")
	}
	if options.MaxActionsPerCrawl < 0 {
		return errkit.New("max-actions-per-crawl must be zero or greater")
	}
	if options.MaxActionRuntime < 0 {
		return errkit.New("max-action-runtime must be zero or greater")
	}
	if options.MaxActionRetries < 0 {
		return errkit.New("max-action-retries must be zero or greater")
	}
	if options.ActionPreflightTimeout < 0 {
		return errkit.New("action-preflight-timeout must be zero or greater")
	}
	if options.ActionSignalTimeout < 0 {
		return errkit.New("action-signal-timeout must be zero or greater")
	}
	if options.ActionQuietPeriod < 0 {
		return errkit.New("action-quiet-period must be zero or greater")
	}

	// Disabling automatic form fill (-aff) for headless navigation due to incorrect implementation.
	// Form filling should be handled via headless actions within the page context
	if options.HeadlessHybrid && options.AutomaticFormFill {
		options.AutomaticFormFill = false
		gologger.Info().Msgf("Automatic form fill (-aff) has been disabled for headless navigation.")
	}

	// Disallow ambiguous engine selection
	if options.Headless && options.HeadlessHybrid {
		return errkit.New("flags -hl (headless) and -hh (hybrid) are mutually exclusive")
	}

	// Warn if -headless or -hh is used with -cwu (Chrome WebSocket URL)
	// The ChromeWSUrl takes precedence and pure headless engine will be used
	if options.Headless && options.ChromeWSUrl != "" {
		gologger.Warning().Msgf("Using -cwu with existing browser session. The -headless flag is redundant.")
		gologger.Info().Msgf("Connecting to Chrome at: %s", options.ChromeWSUrl)
	} else if options.HeadlessHybrid && options.ChromeWSUrl != "" {
		gologger.Warning().Msgf("Using -cwu forces pure headless engine. The -hh (hybrid) flag will be ignored.")
		gologger.Info().Msgf("Connecting to Chrome at: %s (using pure headless engine)", options.ChromeWSUrl)
	} else if options.ChromeWSUrl != "" {
		gologger.Info().Msgf("Connecting to Chrome at: %s (using pure headless engine)", options.ChromeWSUrl)
	}

	if options.AuthCredentials != "" {
		if !strings.Contains(options.AuthCredentials, ":") {
			return errkit.New("auth credentials must be in username:password format")
		}
		if !options.Headless && !options.HeadlessHybrid {
			options.Headless = true
			gologger.Info().Msgf("Headless mode enabled automatically for authenticated crawling.")
		}
	}

	if (options.HeadlessOptionalArguments != nil || options.HeadlessNoSandbox || options.SystemChromePath != "") &&
		!options.Headless && !options.HeadlessHybrid {
		return errkit.New("headless (-hl) or hybrid (-hh) mode is required if -ho, -nos or -scp are set")
	}
	if options.SystemChromePath != "" {
		if !fileutil.FileExists(options.SystemChromePath) {
			return errkit.New("specified system chrome binary does not exist")
		}
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}
	for _, mr := range options.OutputMatchRegex {
		cr, err := regexp.Compile(mr)
		if err != nil {
			return errkit.Wrap(err, "Invalid value for match regex option")
		}
		options.MatchRegex = append(options.MatchRegex, cr)
	}
	for _, fr := range options.OutputFilterRegex {
		cr, err := regexp.Compile(fr)
		if err != nil {
			return errkit.Wrap(err, "Invalid value for filter regex option")
		}
		options.FilterRegex = append(options.FilterRegex, cr)
	}
	if options.KnownFiles != "" && options.MaxDepth < 3 {
		gologger.Info().Msgf("Depth automatically set to 3 to accommodate the `--known-files` option (originally set to %d).", options.MaxDepth)
		options.MaxDepth = 3
	}
	gologger.DefaultLogger.SetFormatter(formatter.NewCLI(options.NoColors))
	return nil
}

// readCustomFormConfig reads custom form fill config
func readCustomFormConfig(formConfig string) error {
	file, err := os.Open(formConfig)
	if err != nil {
		return errkit.Wrap(err, "could not read form config")
	}
	defer func() {
		if err := file.Close(); err != nil {
			gologger.Error().Msgf("Error closing file: %v\n", err)
		}
	}()

	var data utils.FormFillData
	if err := yaml.NewDecoder(file).Decode(&data); err != nil {
		return errkit.Wrap(err, "could not decode form config")
	}
	data.Resolve()
	utils.FormData = data
	return nil
}

// parseInputs parses the inputs returning a slice of URLs
func (r *Runner) parseInputs() []string {
	values := make(map[string]struct{})
	for _, url := range r.options.URLs {
		if url == "" {
			continue
		}
		value := normalizeInput(url)
		if _, ok := values[value]; !ok {
			values[value] = struct{}{}
		}
	}
	if r.stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			value := normalizeInput(scanner.Text())
			if _, ok := values[value]; !ok {
				values[value] = struct{}{}
			}
		}
	}
	final := make([]string, 0, len(values))
	for k := range values {
		final = append(final, k)
	}
	return final
}

func normalizeInput(value string) string {
	return strings.TrimSpace(value)
}

func initExampleFormFillConfig() error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return errkit.Wrap(err, "could not get home directory")
	}
	defaultConfig := filepath.Join(homedir, ".config", "katana", "form-config.yaml")

	if fileutil.FileExists(defaultConfig) {
		return readCustomFormConfig(defaultConfig)
	}
	if err := os.MkdirAll(filepath.Dir(defaultConfig), 0775); err != nil {
		return err
	}
	exampleConfig, err := os.Create(defaultConfig)
	if err != nil {
		return errkit.Wrap(err, "could not get home directory")
	}
	defer func() {
		if err := exampleConfig.Close(); err != nil {
			gologger.Error().Msgf("Error closing example config: %v\n", err)
		}
	}()

	err = yaml.NewEncoder(exampleConfig).Encode(utils.DefaultFormFillData)
	return err
}

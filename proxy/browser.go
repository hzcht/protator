package proxy

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/mxschmitt/playwright-go"
)

// browserPool lazily launches a single headless Chromium and uses it to fetch
// page text for the collector. Not all sites can be reached via plain HTTP, so
// the browser acts as the fallback fetcher.
type browserPool struct {
	headless bool
	timeout  time.Duration

	once    sync.Once
	pw      *playwright.Playwright
	browser playwright.Browser
	err     error

	mu sync.Mutex
}

func newBrowserPool(headless bool, timeout time.Duration) *browserPool {
	return &browserPool{headless: headless, timeout: timeout}
}

// text returns the rendered page text for url, using the fallback browser.
func (b *browserPool) text(ctx context.Context, url string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.once.Do(func() {
		playwright.Install()
		pw, err := playwright.Run()
		if err != nil {
			b.err = err
			return
		}
		br, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
			Headless: playwright.Bool(b.headless),
			Args:     []string{"--disable-blink-features=AutomationControlled"},
		})
		if err != nil {
			pw.Stop()
			b.err = err
			return
		}
		b.pw = pw
		b.browser = br
		log.Printf("collector: browser launched (headless=%v)", b.headless)
	})
	if b.err != nil {
		return "", b.err
	}

	ignoreHTTPS := true
	bctx, err := b.browser.NewContext(playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: &ignoreHTTPS,
	})
	if err != nil {
		return "", err
	}
	defer bctx.Close()

	page, err := bctx.NewPage()
	if err != nil {
		return "", err
	}
	defer page.Close()

	ctx2, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	done := make(chan struct{})
	var content string
	var pageErr error
	go func() {
		defer close(done)
		_, gotoErr := page.Goto(url, playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
			Timeout:   playwright.Float(float64(b.timeout / time.Millisecond)),
		})
		if gotoErr != nil {
			pageErr = gotoErr
			return
		}
		c, err2 := page.Content()
		content = c
		pageErr = err2
	}()

	select {
	case <-done:
	case <-ctx2.Done():
		return "", ctx2.Err()
	}
	return content, pageErr
}

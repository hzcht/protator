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

	// The playwright calls block with no ctx of their own, so the only way to
	// bound them is b.timeout. Wait for both paths to finish before touching
	// page/bctx: returning early leaves the fetch goroutine writing content and
	// calling Close on objects this function has already deferred Close on.
	type result struct {
		content string
		err     error
	}
	done := make(chan result, 1)
	go func() {
		var r result
		_, gotoErr := page.Goto(url, playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
			Timeout:   playwright.Float(float64(b.timeout / time.Millisecond)),
		})
		if gotoErr != nil {
			r.err = gotoErr
		} else {
			r.content, r.err = page.Content()
		}
		done <- r
	}()

	select {
	case r := <-done:
		return r.content, r.err
	case <-ctx2.Done():
		// Playwright's own deadline is b.timeout, which is exactly ctx2's
		// budget, so the goroutine is already returning. Reap it before
		// unwinding so page.Close/bctx.Close cannot race it.
		select {
		case r := <-done:
			return r.content, r.err
		case <-time.After(5 * time.Second):
			// Never leave the browser wedged; give up on leaking this page
			// rather than leaking the fetch itself.
		}
		return "", ctx2.Err()
	}
}

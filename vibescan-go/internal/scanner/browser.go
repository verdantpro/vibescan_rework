package scanner

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/vibescan/vibescan-go/internal/media"
)

// Capture holds the result of screenshotting one HTTP service, mirroring the
// tuple returned by client_agent.py:_capture_http_screenshot.
type Capture struct {
	PNGBase64   string
	Status      *int
	Secured     bool
	Fulltext    string
	CertCN      string
	Phash       string
	FaviconHash string
	Err         string
}

// Browser drives a shared headless Chromium (one process, one tab per capture),
// with bounded concurrency.
type Browser struct {
	allocCtx context.Context
	cancel   context.CancelFunc
	sem      chan struct{}
	delay    time.Duration
	navTO    time.Duration
	fav      *http.Client
}

// NewBrowser launches Chromium and caps concurrent captures.
func NewBrowser(concurrency int, delay time.Duration) *Browser {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.WindowSize(1280, 720),
	)
	// In the container the browser is at a fixed path (e.g. /usr/bin/chromium);
	// let it be pinned explicitly so auto-detection can't pick the wrong binary.
	if p := os.Getenv("VIBESCAN_CHROME_PATH"); p != "" {
		opts = append(opts, chromedp.ExecPath(p))
	}
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	if concurrency < 1 {
		concurrency = 1
	}
	return &Browser{
		allocCtx: ctx,
		cancel:   cancel,
		sem:      make(chan struct{}, concurrency),
		delay:    delay,
		navTO:    15 * time.Second,
		fav: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

// Close shuts down the browser process.
func (b *Browser) Close() { b.cancel() }

// Capture screenshots the service at ip:port, retrying as HTTPS when an http://
// probe hits an SSL protocol error (the server actually speaks TLS).
func (b *Browser) Capture(ctx context.Context, ip string, port int) Capture {
	b.sem <- struct{}{}
	defer func() { <-b.sem }()

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, ip, port)

	c, err := b.capture(ctx, url)
	if err != nil && scheme == "http" && strings.Contains(err.Error(), "ERR_SSL_PROTOCOL_ERROR") {
		c, err = b.capture(ctx, fmt.Sprintf("https://%s:%d", ip, port))
	}
	if err != nil {
		c.Err = err.Error()
	}
	return c
}

func (b *Browser) capture(ctx context.Context, url string) (Capture, error) {
	var c Capture

	tabCtx, cancel := chromedp.NewContext(b.allocCtx)
	defer cancel()
	tabCtx, cancelTO := context.WithTimeout(tabCtx, b.navTO+b.delay+10*time.Second)
	defer cancelTO()

	// First main-frame document response carries the status and TLS subject.
	var firstStatus int
	var certSubject string
	var gotDoc bool
	chromedp.ListenTarget(tabCtx, func(ev any) {
		if e, ok := ev.(*network.EventResponseReceived); ok && !gotDoc && e.Type == network.ResourceTypeDocument {
			gotDoc = true
			firstStatus = int(e.Response.Status)
			if e.Response.SecurityDetails != nil {
				certSubject = e.Response.SecurityDetails.SubjectName
			}
		}
	})

	var pngBuf []byte
	var html, finalURL string
	err := chromedp.Run(tabCtx,
		network.Enable(),
		chromedp.EmulateViewport(1280, 720),
		chromedp.Navigate(url),
		chromedp.Sleep(b.delay),
		chromedp.Location(&finalURL),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
		chromedp.CaptureScreenshot(&pngBuf),
	)
	if err != nil {
		return c, err
	}

	if firstStatus != 0 {
		c.Status = &firstStatus
	}
	c.Secured = strings.HasPrefix(strings.ToLower(finalURL), "https")
	if c.Secured {
		c.CertCN = extractCN(certSubject)
	}
	if len(html) > 32760 {
		html = html[:32760]
	}
	c.Fulltext = html
	c.Phash = media.PerceptualHash(pngBuf)
	c.PNGBase64 = base64.StdEncoding.EncodeToString(pngBuf)
	c.FaviconHash = b.faviconHash(finalURL)
	return c, nil
}

// extractCN pulls the CN from a TLS subject string like "CN=example.com, O=…".
func extractCN(subject string) string {
	if i := strings.Index(subject, "CN="); i >= 0 {
		cn := subject[i+3:]
		if j := strings.Index(cn, ","); j >= 0 {
			cn = cn[:j]
		}
		return strings.TrimSpace(cn)
	}
	return strings.TrimSpace(subject)
}

func (b *Browser) faviconHash(pageURL string) string {
	if pageURL == "" {
		return ""
	}
	resp, err := b.fav.Get(strings.TrimRight(pageURL, "/") + "/favicon.ico")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(body) == 0 {
		return ""
	}
	sum := md5.Sum(body)
	return hex.EncodeToString(sum[:])
}

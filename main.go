package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// sourceMap represents a sourceMap. We only really care about the sources and
// sourcesContent arrays.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// command line args
type config struct {
	outdir          string        // output directory
	url             string        // sourcemap url
	jsurl           string        // javascript url
	dir             string        // directory of sourcemap files to process
	page            string        // page url to crawl for javascript files
	proxy           string        // upstream proxy server
	insecure        bool          // skip tls verification
	headers         headerList    // additional user-supplied http headers
	concurrency     int           // max concurrent requests when crawling a page
	render          bool          // use a headless browser to crawl -page, to catch dynamically-loaded JS
	renderWait      time.Duration // extra time to let dynamic JS load after the page fires its load event
	renderTimeout   time.Duration // hard cap on the whole -render browser session
	renderNoSandbox bool          // launch chrome with --no-sandbox (needed running as root, e.g. in containers)
}

type headerList []string

func (i *headerList) String() string {
	return ""
}

func (i *headerList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// getSourceMap retrieves a sourcemap from a URL or a local file and returns
// its sourceMap. If remoteSource is true, only http/https/data schemes are
// allowed. Local file access is blocked to prevent arbitrary file reads from
// attacker-controlled sourceMappingURL values.
func getSourceMap(source string, headers []string, insecureTLS bool, proxyURL url.URL, remoteSource bool) (m sourceMap, err error) {
	var body []byte
	var client http.Client

	log.Printf("[+] Retrieving Sourcemap from %.1024s...\n", source)

	u, err := url.ParseRequestURI(source)
	if err != nil {
		if remoteSource {
			log.Fatalf("[!] Refusing to read local file from remote sourceMappingURL: %s", source)
		}
		// If it's a file, read it.
		body, err = os.ReadFile(source)
		if err != nil {
			return m, err
		}
	} else {
		if u.Scheme == "http" || u.Scheme == "https" {
			// If it's a URL, get it.
			req, err := http.NewRequest("GET", u.String(), nil)
			tr := &http.Transport{}

			if err != nil {
				return m, err
			}

			if insecureTLS {
				tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}

			if proxyURL != (url.URL{}) {
				tr.Proxy = http.ProxyURL(&proxyURL)
			}

			client = http.Client{
				Transport: tr,
			}

			if len(headers) > 0 {
				headerString := strings.Join(headers, "\r\n") + "\r\n\r\n" // squish all the headers together with CRLFs
				log.Printf("[+] Setting the following headers: \n%s", headerString)

				r := bufio.NewReader(strings.NewReader(headerString))
				tpReader := textproto.NewReader(r)
				mimeHeader, err := tpReader.ReadMIMEHeader()

				if err != nil {
					return m, err
				}

				req.Header = http.Header(mimeHeader)
			}

			res, err := client.Do(req)

			if err != nil {
				return m, err
			}

			body, err = io.ReadAll(res.Body)
			defer res.Body.Close()

			if res.StatusCode != 200 && len(body) > 0 {
				log.Printf("[!] WARNING - non-200 status code: %d - Confirm this URL contains valid source map manually!", res.StatusCode)
				log.Printf("[!] WARNING - sourceMap URL request return != 200 - however, body length > 0 so continuing... ")
			}

			if err != nil {
				return m, err
			}
		} else if u.Scheme == "data" {
			urlchunks := strings.Split(u.Opaque, ",")
			if len(urlchunks) < 2 {
				return m, errors.New("[!] could not parse data URI - expected at least 2 chunks")
			}

			data, err := base64.StdEncoding.DecodeString(urlchunks[1])
			if err != nil {
				return m, err
			}

			body = []byte(data)
		} else {
			if remoteSource {
				log.Fatalf("[!] Refusing to read local file from remote sourceMappingURL: %s", source)
			}
			// If it's a file, read it.
			body, err = os.ReadFile(source)
			if err != nil {
				return m, err
			}
		}
	}
	// Unmarshall the body into the struct.
	log.Printf("[+] Read %d bytes, parsing JSON.\n", len(body))
	err = json.Unmarshal(body, &m)

	if err != nil {
		log.Printf("[!] Error parsing JSON - confirm %s is a valid JS sourcemap", source)
	}

	return
}

// getSourceMapFromJS queries a JavaScript URL, parses its headers and content and looks for sourcemaps
// follows the rules outlined in https://tc39.es/source-map-spec/#linking-generated-code
func getSourceMapFromJS(jsurl string, headers []string, insecureTLS bool, proxyURL url.URL) (m sourceMap, err error) {
	var client http.Client

	log.Printf("[+] Retrieving JavaScript from URL: %s.\n", jsurl)

	// perform the request
	u, err := url.ParseRequestURI(jsurl)
	if err != nil {
		return m, err
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	tr := &http.Transport{}

	if err != nil {
		return m, err
	}

	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if proxyURL != (url.URL{}) {
		tr.Proxy = http.ProxyURL(&proxyURL)
	}

	client = http.Client{
		Transport: tr,
	}

	if len(headers) > 0 {
		headerString := strings.Join(headers, "\r\n") + "\r\n\r\n" // squish all the headers together with CRLFs
		log.Printf("[+] Setting the following headers: \n%s", headerString)

		r := bufio.NewReader(strings.NewReader(headerString))
		tpReader := textproto.NewReader(r)
		mimeHeader, err := tpReader.ReadMIMEHeader()

		if err != nil {
			return m, err
		}

		req.Header = http.Header(mimeHeader)
	}

	res, err := client.Do(req)

	if err != nil {
		return m, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return m, fmt.Errorf("[!] non-200 status code: %d", res.StatusCode)
	}

	var sourceMap string

	// check for SourceMap and X-SourceMap (deprecated) headers
	if sourceMap = res.Header.Get("SourceMap"); sourceMap == "" {
		sourceMap = res.Header.Get("X-SourceMap")
	}

	if sourceMap != "" {
		log.Printf("[.] Found SourceMap URI in response headers: %.1024s...", sourceMap)
	} else {
		// parse the javascript
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return m, err
		}

		// JS file can have multiple source maps in it, but only the last line is valid https://sourcemaps.info/spec.html#h.lmz475t4mvbx
		re := regexp.MustCompile(`\/\/[@#] sourceMappingURL=(.*)`)
		match := re.FindAllSubmatch(body, -1)

		if len(match) != 0 {
			// only the sourcemap at the end of the file should be valid
			sourceMap = string(match[len(match)-1][1])
			log.Printf("[.] Found SourceMap in JavaScript body: %.1024s...", sourceMap)
		}
	}

	// this introduces a forced request bug if the JS file we're parsing is
	// malicious and forces us to make a request out to something dodgy - take care
	if sourceMap != "" {
		var sourceMapURL *url.URL
		// handle absolute/relative rules
		sourceMapURL, err = url.ParseRequestURI(sourceMap)
		if err != nil {
			// relative url...
			sourceMapURL, err = u.Parse(sourceMap)
			if err != nil {
				return m, err
			}
		}

		return getSourceMap(sourceMapURL.String(), headers, insecureTLS, proxyURL, true)
	}

	err = errors.New("[!] No sourcemap URL found")
	return
}

// fetchURL retrieves the raw body of a URL, applying the same proxy/TLS/header
// options used elsewhere in this tool.
func fetchURL(rawURL string, headers []string, insecureTLS bool, proxyURL url.URL) ([]byte, error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{}
	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if proxyURL != (url.URL{}) {
		tr.Proxy = http.ProxyURL(&proxyURL)
	}
	client := http.Client{Transport: tr}

	if len(headers) > 0 {
		headerString := strings.Join(headers, "\r\n") + "\r\n\r\n"
		r := bufio.NewReader(strings.NewReader(headerString))
		tpReader := textproto.NewReader(r)
		mimeHeader, err := tpReader.ReadMIMEHeader()
		if err != nil {
			return nil, err
		}
		req.Header = http.Header(mimeHeader)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("[!] non-200 status code: %d", res.StatusCode)
	}

	return io.ReadAll(res.Body)
}

// extractScriptURLs finds <script src="..."> references in an HTML body and
// resolves them against the page's URL. This only sees scripts present in the
// initial HTML - JS injected at runtime (e.g. lazily-loaded SPA chunks) needs
// a rendered-browser crawl instead, which this static extractor doesn't do.
func extractScriptURLs(body []byte, base *url.URL) []string {
	re := regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	matches := re.FindAllSubmatch(body, -1)

	seen := make(map[string]bool)
	var urls []string

	for _, match := range matches {
		raw := strings.TrimSpace(string(match[1]))
		if raw == "" || strings.HasPrefix(raw, "data:") {
			continue
		}

		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}

		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}

		s := resolved.String()
		if !seen[s] {
			seen[s] = true
			urls = append(urls, s)
		}
	}

	return urls
}

// subdirForURL builds a filesystem-safe output subdirectory from a JS URL's
// host and path, so sources extracted from different JS files don't collide
// with each other on disk.
func subdirForURL(jsURL string) string {
	u, err := url.Parse(jsURL)
	if err != nil {
		return "unknown"
	}

	p := strings.TrimSuffix(u.Path, filepath.Ext(u.Path))
	p = strings.Trim(p, "/")

	dir := filepath.Join(u.Host, filepath.FromSlash(p))
	if runtime.GOOS == "windows" {
		dir = cleanWindows(dir)
	}

	return dir
}

// crawlPage fetches an HTML page and returns the absolute URLs of every
// JavaScript file referenced via <script src> in the initial response body.
func crawlPage(pageURL string, headers []string, insecureTLS bool, proxyURL url.URL) ([]string, error) {
	log.Printf("[+] Crawling page %s for JavaScript files...\n", pageURL)

	base, err := url.ParseRequestURI(pageURL)
	if err != nil {
		return nil, err
	}

	body, err := fetchURL(pageURL, headers, insecureTLS, proxyURL)
	if err != nil {
		return nil, err
	}

	return extractScriptURLs(body, base), nil
}

// parseHeaderList converts curl-style "Key: Value" header strings into the
// map form chromedp's network domain expects.
func parseHeaderList(headers []string) (network.Headers, error) {
	if len(headers) == 0 {
		return nil, nil
	}

	headerString := strings.Join(headers, "\r\n") + "\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(headerString))
	tpReader := textproto.NewReader(r)
	mimeHeader, err := tpReader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	result := make(network.Headers, len(mimeHeader))
	for k, v := range mimeHeader {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result, nil
}

// crawlPageRendered uses a headless browser to load pageURL and returns the
// absolute URLs of every JavaScript file it requests - including scripts
// loaded dynamically after the initial page load (SPA chunks, lazy imports,
// XHR-injected <script> tags), which crawlPage's static HTML scrape misses.
// Requires a local Chrome/Chromium install. This renders whatever the target
// page serves, including any attacker-controlled JS, so unlike the rest of
// this tool it doesn't disable the browser sandbox unless noSandbox is set.
func crawlPageRendered(pageURL string, headers []string, insecureTLS, noSandbox bool, proxyURL url.URL, waitAfterLoad, timeout time.Duration) ([]string, error) {
	log.Printf("[+] Rendering page %s in a headless browser to find JavaScript files...\n", pageURL)

	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	if insecureTLS {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	if noSandbox {
		opts = append(opts, chromedp.NoSandbox)
	}
	if proxyURL != (url.URL{}) {
		opts = append(opts, chromedp.ProxyServer(proxyURL.String()))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	extraHeaders, err := parseHeaderList(headers)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	seen := make(map[string]bool)
	var scriptURLs []string

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		e, ok := ev.(*network.EventResponseReceived)
		if !ok || e.Response == nil {
			return
		}

		isJS := e.Type == network.ResourceTypeScript || strings.Contains(strings.ToLower(e.Response.MimeType), "javascript")
		if !isJS {
			return
		}

		u, err := url.Parse(e.Response.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}

		mu.Lock()
		defer mu.Unlock()
		if !seen[e.Response.URL] {
			seen[e.Response.URL] = true
			scriptURLs = append(scriptURLs, e.Response.URL)
		}
	})

	actions := []chromedp.Action{network.Enable()}
	if extraHeaders != nil {
		actions = append(actions, network.SetExtraHTTPHeaders(extraHeaders))
	}
	actions = append(actions, chromedp.Navigate(pageURL), chromedp.Sleep(waitAfterLoad))

	if err := chromedp.Run(ctx, actions...); err != nil {
		return nil, err
	}

	return scriptURLs, nil
}

// writeFile writes content to file at path p.
func writeFile(p string, content string) error {
	p = filepath.Clean(p)

	if _, err := os.Stat(filepath.Dir(p)); os.IsNotExist(err) {
		// Using MkdirAll here is tricky, because even if we fail, we might have
		// created some of the parent directories.
		err = os.MkdirAll(filepath.Dir(p), 0700)
		if err != nil {
			return err
		}
	}

	log.Printf("[+] Writing %d bytes to %s.\n", len(content), p)
	return os.WriteFile(p, []byte(content), 0600)
}

// cleanWindows replaces the illegal characters from a path with `-`.
func cleanWindows(p string) string {
	m1 := regexp.MustCompile(`[?%*|:"<>]`)
	return m1.ReplaceAllString(p, "")
}

// processSourceMap extracts source files from a parsed sourcemap into outdir.
func processSourceMap(sm sourceMap, outdir string) error {
	log.Printf("[+] Retrieved Sourcemap with version %d, containing %d entries.\n", sm.Version, len(sm.Sources))

	if len(sm.Sources) == 0 {
		return errors.New("no sources found")
	}

	if len(sm.SourcesContent) == 0 {
		return errors.New("no source content found")
	}

	if sm.Version != 3 {
		log.Println("[!] Sourcemap is not version 3. This is untested!")
	}

	if _, err := os.Stat(outdir); os.IsNotExist(err) {
		err = os.MkdirAll(outdir, 0700)
		if err != nil {
			return err
		}
	}

	for i, sourcePath := range sm.Sources {
		// sourcesContent may be shorter than sources (the spec allows it).
		if i >= len(sm.SourcesContent) {
			log.Printf("[!] No source content for %s, skipping.", sourcePath)
			continue
		}

		sourcePath = "/" + sourcePath // path.Clean will ignore a leading '..', must be a '/..'
		// If on windows, clean the sourcepath.
		if runtime.GOOS == "windows" {
			sourcePath = cleanWindows(sourcePath)
		}

		// Use filepath.Join. https://parsiya.net/blog/2019-03-09-path.join-considered-harmful/
		scriptPath, scriptData := filepath.Join(outdir, filepath.Clean(sourcePath)), sm.SourcesContent[i]
		err := writeFile(scriptPath, scriptData)
		if err != nil {
			log.Printf("Error writing %s file: %s", scriptPath, err)
		}
	}

	return nil
}

func main() {
	var proxyURL url.URL
	var conf config
	var err error

	flag.StringVar(&conf.outdir, "output", "", "Source file output directory - REQUIRED")
	flag.StringVar(&conf.url, "url", "", "URL or path to the Sourcemap file")
	flag.StringVar(&conf.jsurl, "jsurl", "", "URL to JavaScript file")
	flag.StringVar(&conf.dir, "dir", "", "Directory of .map files to process recursively")
	flag.StringVar(&conf.page, "page", "", "URL of a page to crawl for JavaScript files, processing every sourcemap found")
	flag.StringVar(&conf.proxy, "proxy", "", "Proxy URL")
	help := flag.Bool("help", false, "Show help")
	flag.BoolVar(&conf.insecure, "insecure", false, "Ignore invalid TLS certificates")
	flag.Var(&conf.headers, "header", "A header to send with the request, similar to curl's -H. Can be set multiple times, EG: \"./sourcemapper --header \"Cookie: session=bar\" --header \"Authorization: blerp\"")
	flag.IntVar(&conf.concurrency, "concurrency", 5, "Max concurrent requests when crawling a page with -page")
	flag.BoolVar(&conf.render, "render", false, "With -page, load the page in a headless Chrome/Chromium instance and capture JavaScript loaded dynamically (SPA chunks, lazy imports), not just what's in the initial HTML")
	flag.DurationVar(&conf.renderWait, "render-wait", 3*time.Second, "With -render, extra time to let dynamically-loaded JavaScript fire after the page loads")
	flag.DurationVar(&conf.renderTimeout, "render-timeout", 30*time.Second, "With -render, hard timeout for the whole headless browser session")
	flag.BoolVar(&conf.renderNoSandbox, "render-no-sandbox", false, "With -render, launch Chrome with --no-sandbox (needed when running as root, e.g. in a container)")
	flag.Parse()

	if *help || (conf.url == "" && conf.jsurl == "" && conf.dir == "" && conf.page == "") || conf.outdir == "" {
		flag.Usage()
		return
	}

	// Ensure only one input mode is specified
	inputModes := 0
	if conf.url != "" {
		inputModes++
	}
	if conf.jsurl != "" {
		inputModes++
	}
	if conf.dir != "" {
		inputModes++
	}
	if conf.page != "" {
		inputModes++
	}
	if inputModes > 1 {
		log.Println("[!] Only one of -url, -jsurl, -dir, or -page can be specified")
		flag.Usage()
		return
	}

	if conf.proxy != "" {
		p, err := url.Parse(conf.proxy)
		if err != nil {
			log.Fatal(err)
		}
		proxyURL = *p
	}

	if conf.dir != "" {
		// Walk the directory and process all .map files
		var mapFiles []string
		err = filepath.Walk(conf.dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".map") {
				mapFiles = append(mapFiles, path)
			}
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
		if len(mapFiles) == 0 {
			log.Fatalf("[!] No .map files found in %s", conf.dir)
		}
		log.Printf("[+] Found %d .map files in %s", len(mapFiles), conf.dir)

		for _, mapFile := range mapFiles {
			log.Printf("[+] Processing: %s", mapFile)
			sm, err := getSourceMap(mapFile, conf.headers, conf.insecure, proxyURL, false)
			if err != nil {
				log.Printf("[!] Error reading %s: %s, skipping.", mapFile, err)
				continue
			}
			if err := processSourceMap(sm, conf.outdir); err != nil {
				log.Printf("[!] Error processing %s: %s, skipping.", mapFile, err)
				continue
			}
		}
	} else if conf.page != "" {
		var scriptURLs []string
		var err error
		if conf.render {
			scriptURLs, err = crawlPageRendered(conf.page, conf.headers, conf.insecure, conf.renderNoSandbox, proxyURL, conf.renderWait, conf.renderTimeout)
		} else {
			scriptURLs, err = crawlPage(conf.page, conf.headers, conf.insecure, proxyURL)
		}
		if err != nil {
			log.Fatal(err)
		}
		if len(scriptURLs) == 0 {
			log.Fatalf("[!] No JavaScript files found on %s", conf.page)
		}
		log.Printf("[+] Found %d JavaScript file(s) on %s", len(scriptURLs), conf.page)

		concurrency := conf.concurrency
		if concurrency < 1 {
			concurrency = 1
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		sem := make(chan struct{}, concurrency)
		found, skipped := 0, 0

		for _, jsURL := range scriptURLs {
			wg.Add(1)
			sem <- struct{}{}

			go func(jsURL string) {
				defer wg.Done()
				defer func() { <-sem }()

				sm, err := getSourceMapFromJS(jsURL, conf.headers, conf.insecure, proxyURL)
				if err != nil {
					log.Printf("[!] %s: %s, skipping.", jsURL, err)
					mu.Lock()
					skipped++
					mu.Unlock()
					return
				}

				outPath := filepath.Join(conf.outdir, subdirForURL(jsURL))
				if err := processSourceMap(sm, outPath); err != nil {
					log.Printf("[!] Error processing sourcemap for %s: %s, skipping.", jsURL, err)
					mu.Lock()
					skipped++
					mu.Unlock()
					return
				}

				mu.Lock()
				found++
				mu.Unlock()
			}(jsURL)
		}

		wg.Wait()
		log.Printf("[+] Crawl of %s complete: %d sourcemap(s) extracted, %d skipped/failed", conf.page, found, skipped)
	} else {
		var sm sourceMap

		if conf.url != "" {
			if sm, err = getSourceMap(conf.url, conf.headers, conf.insecure, proxyURL, false); err != nil {
				log.Fatal(err)
			}
		} else if conf.jsurl != "" {
			if sm, err = getSourceMapFromJS(conf.jsurl, conf.headers, conf.insecure, proxyURL); err != nil {
				log.Fatal(err)
			}
		}

		if err := processSourceMap(sm, conf.outdir); err != nil {
			log.Fatal(err)
		}
	}

	log.Println("[+] Done")
}

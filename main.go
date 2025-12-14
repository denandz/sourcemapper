package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
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
	outdir   string     // output directory
	url      string     // sourcemap url
	jsurl    string     // javascript url
	file     string     // file containing URLs
	stdin    bool       // read URLs from stdin
	proxy    string     // upstream proxy server
	insecure bool       // skip tls verification
	headers  headerList // additional user-supplied http headers
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
// its sourceMap.
func getSourceMap(source string, headers []string, insecureTLS bool, proxyURL url.URL) (m sourceMap, err error) {
	var body []byte
	var client http.Client

	log.Printf("[+] Retrieving Sourcemap from %.1024s...\n", source)

	u, err := url.ParseRequestURI(source)
	if err != nil {
		// If it's a file, read it.
		body, err = os.ReadFile(source)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		if u.Scheme == "http" || u.Scheme == "https" {
			// If it's a URL, get it.
			req, err := http.NewRequest("GET", u.String(), nil)
			tr := &http.Transport{}

			if err != nil {
				log.Fatalln(err)
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
					log.Fatalln(err)
				}

				req.Header = http.Header(mimeHeader)
			}

			res, err := client.Do(req)

			if err != nil {
				log.Fatalln(err)
			}

			body, err = io.ReadAll(res.Body)
			defer res.Body.Close()

			if res.StatusCode != 200 && len(body) > 0 {
				log.Printf("[!] WARNING - non-200 status code: %d - Confirm this URL contains valid source map manually!", res.StatusCode)
				log.Printf("[!] WARNING - sourceMap URL request return != 200 - however, body length > 0 so continuing... ")
			}

			if err != nil {
				log.Fatalln(err)
			}
		} else if u.Scheme == "data" {
			urlchunks := strings.Split(u.Opaque, ",")
			if len(urlchunks) < 2 {
				log.Fatalf("[!] Could not parse data URI - expected atleast 2 chunks but got %d\n", len(urlchunks))
			}

			data, err := base64.StdEncoding.DecodeString(urlchunks[1])
			if err != nil {
				log.Fatal("[!] Error base64 decoding", err)
			}

			body = []byte(data)
		} else {
			// If it's a file, read it.
			body, err = os.ReadFile(source)
			if err != nil {
				log.Fatalln(err)
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
		log.Fatal(err)
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	tr := &http.Transport{}

	if err != nil {
		log.Fatalln(err)
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
			log.Fatalln(err)
		}

		req.Header = http.Header(mimeHeader)
	}

	res, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
	}

	if res.StatusCode != 200 {
		log.Fatalf("[!] non-200 status code: %d", res.StatusCode)
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
			log.Fatalln(err)
		}
		defer res.Body.Close()

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
				log.Fatal(err)
			}
		}

		return getSourceMap(sourceMapURL.String(), headers, insecureTLS, proxyURL)
	}

	err = errors.New("[!] No sourcemap URL found")
	return
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

// readURLsFromFile reads URLs from a file, one URL per line
func readURLsFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// readURLsFromStdin reads URLs from stdin, one URL per line
func readURLsFromStdin() ([]string, error) {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// processSourceMap processes a single sourcemap and writes its sources to disk
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
		err = os.Mkdir(outdir, 0700)
		if err != nil {
			return err
		}
	}

	for i, sourcePath := range sm.Sources {
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

// getSourceMapFromURL retrieves a sourcemap from a URL, automatically detecting
// whether it's a JavaScript file or sourcemap based on the URL extension
func getSourceMapFromURL(urlStr string, headers []string, insecureTLS bool, proxyURL url.URL) (sourceMap, error) {
	// Parse the URL to extract the path without query parameters or fragments
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		// If URL parsing fails, fall back to simple string matching
		if strings.HasSuffix(urlStr, ".js.map") || strings.HasSuffix(urlStr, ".map") {
			return getSourceMap(urlStr, headers, insecureTLS, proxyURL)
		} else if strings.HasSuffix(urlStr, ".js") {
			return getSourceMapFromJS(urlStr, headers, insecureTLS, proxyURL)
		}
		return getSourceMap(urlStr, headers, insecureTLS, proxyURL)
	}

	// Check the path component for file extensions
	path := parsedURL.Path
	if strings.HasSuffix(path, ".js.map") || strings.HasSuffix(path, ".map") {
		return getSourceMap(urlStr, headers, insecureTLS, proxyURL)
	} else if strings.HasSuffix(path, ".js") {
		return getSourceMapFromJS(urlStr, headers, insecureTLS, proxyURL)
	}
	// Default to treating as sourcemap for other extensions
	return getSourceMap(urlStr, headers, insecureTLS, proxyURL)
}

// processURLs processes multiple URLs from a list
func processURLs(urls []string, source string, outdir string, headers []string, insecureTLS bool, proxyURL url.URL) {
	if len(urls) == 0 {
		log.Fatalf("[!] No URLs found in %s", source)
	}

	log.Printf("[+] Processing %d URLs from %s\n", len(urls), source)

	for idx, urlStr := range urls {
		log.Printf("[+] Processing URL %d/%d: %s\n", idx+1, len(urls), urlStr)

		sm, err := getSourceMapFromURL(urlStr, headers, insecureTLS, proxyURL)
		if err != nil {
			log.Printf("[!] Error processing URL %s: %v\n", urlStr, err)
			continue
		}

		if err := processSourceMap(sm, outdir); err != nil {
			log.Printf("[!] Error processing sourcemap for %s: %v\n", urlStr, err)
		}
	}

	log.Println("[+] Done")
}

func main() {
	var proxyURL url.URL
	var conf config
	var err error

	flag.StringVar(&conf.outdir, "output", "", "Source file output directory - REQUIRED")
	flag.StringVar(&conf.url, "url", "", "URL or path to the Sourcemap file - cannot be used with jsurl, file, or stdin")
	flag.StringVar(&conf.jsurl, "jsurl", "", "URL to JavaScript file - cannot be used with url, file, or stdin")
	flag.StringVar(&conf.file, "file", "", "File containing URLs (one per line) - cannot be used with url, jsurl, or stdin")
	flag.BoolVar(&conf.stdin, "stdin", false, "Read URLs from stdin (one per line) - cannot be used with url, jsurl, or file")
	flag.StringVar(&conf.proxy, "proxy", "", "Proxy URL")
	help := flag.Bool("help", false, "Show help")
	flag.BoolVar(&conf.insecure, "insecure", false, "Ignore invalid TLS certificates")
	flag.Var(&conf.headers, "header", "A header to send with the request, similar to curl's -H. Can be set multiple times, EG: \"./sourcemapper --header \"Cookie: session=bar\" --header \"Authorization: blerp\"")
	flag.Parse()

	if *help || (conf.url == "" && conf.jsurl == "" && conf.file == "" && !conf.stdin) || conf.outdir == "" {
		flag.Usage()
		return
	}

	// Check for mutually exclusive flags
	flagCount := 0
	if conf.url != "" {
		flagCount++
	}
	if conf.jsurl != "" {
		flagCount++
	}
	if conf.file != "" {
		flagCount++
	}
	if conf.stdin {
		flagCount++
	}

	if flagCount > 1 {
		log.Println("[!] Only one of -url, -jsurl, -file, or -stdin can be specified")
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

	// Process URLs from stdin if -stdin flag is provided
	if conf.stdin {
		urls, err := readURLsFromStdin()
		if err != nil {
			log.Fatalf("[!] Error reading from stdin: %v", err)
		}
		processURLs(urls, "stdin", conf.outdir, conf.headers, conf.insecure, proxyURL)
		return
	}

	// Process URLs from file if -file flag is provided
	if conf.file != "" {
		urls, err := readURLsFromFile(conf.file)
		if err != nil {
			log.Fatalf("[!] Error reading file: %v", err)
		}
		processURLs(urls, "file "+conf.file, conf.outdir, conf.headers, conf.insecure, proxyURL)
		return
	}

	var sm sourceMap

	// Process single URL (original behavior)
	if conf.url != "" {
		if sm, err = getSourceMap(conf.url, conf.headers, conf.insecure, proxyURL); err != nil {
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

	log.Println("[+] Done")
}

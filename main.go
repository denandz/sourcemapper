package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
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

type headerList []string

func (i *headerList) String() string {
	return ""
}

func (i *headerList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// isURL tries to figure out if a string is a URL or not.
func isURL(source string) bool {

	// Try to parse the URL, if it's not valid we will assume source is a file.
	u, parseErr := url.ParseRequestURI(source)
	if parseErr != nil {
		return false
	}

	// Full Windows paths like `C:\path\to\file` (escaped as
	// `C:\\path\\to\\file`) are accepted so we need to check the scheme. Scheme
	// is returned in lowercase.
	if u.Scheme == "http" || u.Scheme == "https" {
		return true
	}
	return false
}

// getSourceMap retrieves a sourcemap from a URL or a local file and returns
// its sourceMap.
func getSourceMap(source string, headers []string, insecureTLS bool, proxyURL url.URL) (m sourceMap, err error) {
	var body []byte
	var client http.Client

	log.Printf("[+] Retrieving Sourcemap from %s.\n", source)

	if isURL(source) {
		// If it's a URL, get it.
		req, err := http.NewRequest("GET", source, nil)
		tr := &http.Transport{}

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

		body, err = ioutil.ReadAll(res.Body)
		defer res.Body.Close()

		if res.StatusCode != 200 && len(body) > 0 {
			log.Printf("[!] WARNING - non-200 status code: %d", res.StatusCode)
			log.Printf("[!] WARNING - sourceMap URL request return != 200 - however, body length > 0 so continuing... ")
		}

		if err != nil {
			log.Fatalln(err)
		}
	} else {
		// If it's a file, read it.
		body, err = ioutil.ReadFile(source)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// Unmarshall the body into the struct.
	log.Printf("[+] Read %d bytes, parsing JSON.\n", len(body))
	err = json.Unmarshal(body, &m)

	if err != nil {
		log.Printf("[!] Error parsing JSON - confirm %s a valid JS sourcemap", source)
	}

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
	return ioutil.WriteFile(p, []byte(content), 0600)
}

// cleanWindows replaces the illegal characters from a path with `-`.
func cleanWindows(p string) string {
	m1 := regexp.MustCompile(`[?%*|:"<>]`)
	return m1.ReplaceAllString(p, "")
}

func main() {

	var headers headerList
	var proxyURL url.URL

	outDir := flag.String("output", "", "Source file output directory - REQUIRED")
	urlflag := flag.String("url", "", "URL or path to the Sourcemap file - REQUIRED")
	proxy := flag.String("proxy", "", "Proxy URL")
	help := flag.Bool("help", false, "Show help")
	insecure := flag.Bool("insecure", false, "Ignore invalid TLS certificates")
	flag.Var(&headers, "header", "A header to send with the request, similar to curl's -H. Can be set multiple times, EG: \"./sourcemapper --header \"Cookie: session=bar\" --header \"Authorization: blerp\"")
	flag.Parse()

	if *help || *urlflag == "" || *outDir == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *proxy != "" {
		p, err := url.Parse(*proxy)
		if err != nil {
			log.Fatal(err)
		}
		proxyURL = *p
	}

	sm, err := getSourceMap(*urlflag, headers, *insecure, proxyURL)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("[+] Retrieved Sourcemap with version %d, containing %d entries.\n", sm.Version, len(sm.Sources))

	if len(sm.Sources) == 0 {
		log.Fatal("No sources found.")
	}

	if len(sm.SourcesContent) == 0 {
		log.Fatal("No source content found.")
	}

	if sm.Version != 3 {
		log.Println("[!] Sourcemap is not version 3. This is untested!")
	}

	if _, err := os.Stat(*outDir); os.IsNotExist(err) {
		err = os.Mkdir(*outDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	for i, sourcePath := range sm.Sources {
		sourcePath = "/" + sourcePath // path.Clean will ignore a leading '..', must be a '/..'
		// If on windows, clean the sourcepath.
		if runtime.GOOS == "windows" {
			sourcePath = cleanWindows(sourcePath)
		}

		// Use filepath.Join. https://parsiya.net/blog/2019-03-09-path.join-considered-harmful/
		scriptPath, scriptData := filepath.Join(*outDir, filepath.Clean(sourcePath)), sm.SourcesContent[i]
		err := writeFile(scriptPath, scriptData)
		if err != nil {
			log.Printf("Error writing %s file: %s", scriptPath, err)
		}
	}

	log.Println("[+] Done")
}

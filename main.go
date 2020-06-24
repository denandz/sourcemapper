package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

// sourceMap represents a sourceMap. We only really care about the sources and
// sourcesContent arrays.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
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
func getSourceMap(source string) (m sourceMap, err error) {
	var body []byte

	fmt.Printf("[+] Retrieving Sourcemap from %s.\n", source)

	if isURL(source) {
		// If it's a URL, get it.
		var res *http.Response
		res, err = http.Get(source)
		if err != nil {
			return // == return m, err
		}

		if res.StatusCode != 200 {
			return m, fmt.Errorf("sourceMap URL request return != 200")
		}

		body, err = ioutil.ReadAll(res.Body)
		defer res.Body.Close()
		if err != nil {
			return
		}
	} else {
		// If it's a file, read it.
		body, err = ioutil.ReadFile(source)
		if err != nil {
			return
		}
	}

	// Unmarshall the body into the struct.
	fmt.Printf("[+] Read %d bytes, parsing JSON.\n", len(body))
	err = json.Unmarshal(body, &m)
	// if err != nil {
	// 	log.Fatalf("Error parsing JSON: %s", err)
	// }

	// No need to check for errors here, we can just return (m, err)
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

	fmt.Printf("[+] Writing %d bytes to %s.\n", len(content), p)
	return ioutil.WriteFile(p, []byte(content), 0600)
}

// cleanWindows replaces the illegal characters from a path with `-`.
func cleanWindows(p string) string {
	m1 := regexp.MustCompile(`[?%*|:"<>]`)
	return m1.ReplaceAllString(p, "")
}

func main() {
	outDir := flag.String("output", "", "Source file output directory")
	url := flag.String("url", "", "URL or path to the Sourcemap file")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help || *url == "" || *outDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	sm, err := getSourceMap(*url)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("%+v\n", sm)

	fmt.Printf("[+] Retrieved Sourcemap with version %d, containing %d entries.\n", sm.Version, len(sm.Sources))

	if len(sm.Sources) == 0 {
		log.Fatal("No sources found.")
	}

	if len(sm.SourcesContent) == 0 {
		log.Fatal("No source content found.")
	}

	if sm.Version != 3 {
		fmt.Println("[!] Sourcemap is not version 3. This is untested!")
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

	fmt.Println("[+] Done")
}

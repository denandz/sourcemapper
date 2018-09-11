package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path"
)

// sourceMap struct - We only really care about the sources and sourcesContent arrays
type sourceMap struct {
    Version        int      `json:"version"`
    Sources        []string `json:"sources"`
    SourcesContent []string `json:"sourcesContent"`
}

func getSourceMap(url string) sourceMap {
    var m sourceMap

    res, err := http.Get(url)
    if err != nil {
        log.Fatal(err)
    }

    if res.StatusCode != 200 {
        log.Fatal("sourceMap URL request return != 200")
    }

    body, err := ioutil.ReadAll(res.Body)
    fmt.Printf("[+] Read %d bytes, parsing JSON\n", len(body))
    res.Body.Close()

    if err != nil {
        log.Fatal(err)
    }

    err = json.Unmarshal(body, &m)
    if err != nil {
        log.Fatalf("Error parsing JSON: %s", err)
    }

    return m
}

func writeFile(p string, content string) {
    p = path.Clean(p)
    fmt.Printf("[+] Writing %d bytes to %s\n", len(content), p)

    if _, err := os.Stat(path.Dir(p)); os.IsNotExist(err) {
        err = os.MkdirAll(path.Dir(p), 0700)
        if err != nil {
            log.Fatal(err)
        }
    }

    err := ioutil.WriteFile(p, []byte(content), 0600)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    outDir := flag.String("output", "", "Source file output directory")
    url := flag.String("url", "", "URL to the Sourcemap file")
    help := flag.Bool("help", false, "Show help")
    flag.Parse()

    if *help || *url == "" || *outDir == "" {
        flag.Usage()
        os.Exit(1)
    }

    fmt.Printf("[+] Retriving Sourcemap from %s\n", *url)

    sm := getSourceMap(*url)
    //fmt.Printf("%+v\n", sm)

    fmt.Printf("[+] Retrieved Sourcemap with version %d, containing %d entries\n", sm.Version, len(sm.Sources))

    if len(sm.Sources) == 0 {
        log.Fatal("No sources found")
    }

    if len(sm.SourcesContent) == 0 {
        log.Fatal("No source content found")
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
        scriptPath, scriptData := path.Join(*outDir, path.Clean(sourcePath)), sm.SourcesContent[i]
        writeFile(scriptPath, scriptData)
    }

    fmt.Println("[+] done")
}

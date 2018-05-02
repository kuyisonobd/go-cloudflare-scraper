package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	cookiejar "github.com/jmoiron/persistent-cookiejar"

	scraper "github.com/jmoiron/go-cloudflare-scraper"
)

type Getter interface {
	Get(url string) (*http.Response, error)
}

func makeRequest(c Getter, url string) {
	t := time.Now()

	log.Printf("Requesting %s", url)
	resp, err := c.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("Fetched %s in %s, %d bytes (status %d)",
		url, time.Now().Sub(t), len(body), resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		log.Fatal("Invalid response code")
	}
}

func main() {
	flag.Parse()
	jar, _ := cookiejar.New(nil)
	client := scraper.NewClientJar(jar)
	makeRequest(client, flag.Arg(0))
}

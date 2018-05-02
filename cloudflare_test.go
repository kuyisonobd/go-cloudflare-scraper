package scraper

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransport(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadFile("_examples/challenge.html")
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "cloudflare-nginx")
		w.WriteHeader(503)
		w.Write(b)
	}))
	defer ts.Close()

	c := NewClient()

	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestChallenge(t *testing.T) {
	// >>> cfscrape.CloudflareScraper().
	// ... solve_challenge(open("_examples/challenge.html").read(), "x"*18)
	// '27.5744148617'
	expected := "27.5744148617"

	f, err := ioutil.ReadFile("_examples/challenge.html")
	if err != nil {
		t.Fatal(err)
	}

	js, err := extractJS(string(f), "xxxxxxxxxxxxxxxxxx")
	if err != nil {
		t.Fatal(err)
	}

	val, err := evaluateJS(js)
	if err != nil {
		t.Fatal(err)
	}

	if fmt.Sprint(val) != expected {
		t.Errorf("value %f != %s", val, expected)
	}
}

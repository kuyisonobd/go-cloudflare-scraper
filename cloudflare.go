package scraper

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
)

var uas = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/65.0.3325.181 Chrome/65.0.3325.181 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 7.0; Moto G (5) Build/NPPS25.137-93-8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.137 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
}

var rng = rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

func randomAgent() string {
	return uas[rng.Perm(len(uas))[0]]
}

type Transport struct {
	upstream http.RoundTripper
	cookies  http.CookieJar
}

func NewTransport(upstream http.RoundTripper) (*Transport, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &Transport{upstream, jar}, nil
}

func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", randomAgent())
	}

	resp, err := t.upstream.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	isCloudflareServer := strings.HasPrefix(resp.Header.Get("Server"), "cloudflare")
	// Check if Cloudflare anti-bot is on
	for resp.StatusCode == 503 && isCloudflareServer {
		log.Printf("Solving challenge for %s", resp.Request.URL.Hostname())
		resp, err = t.solveChallenge(resp)
		if err != nil {
			return resp, err
		}
	}

	return resp, err
}

var jschlRegexp = regexp.MustCompile(`name="jschl_vc" value="(\w+)"`)
var passRegexp = regexp.MustCompile(`name="pass" value="(.+?)"`)

func (t Transport) solveChallenge(resp *http.Response) (*http.Response, error) {
	time.Sleep(time.Second * 8) // Cloudflare requires a delay before solving the challenge

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(b))

	var params = make(url.Values)

	if m := jschlRegexp.FindStringSubmatch(string(b)); len(m) > 0 {
		params.Set("jschl_vc", m[1])
	}

	if m := passRegexp.FindStringSubmatch(string(b)); len(m) > 0 {
		params.Set("pass", m[1])
	}

	chkURL, _ := url.Parse("/cdn-cgi/l/chk_jschl")
	u := resp.Request.URL.ResolveReference(chkURL)

	js, err := extractJS(string(b), resp.Request.URL.Host)
	if err != nil {
		return nil, err
	}

	answer, err := evaluateJS(js)
	if err != nil {
		return nil, err
	}

	params.Set("jschl_answer", fmt.Sprint(float64(answer)))

	req, err := http.NewRequest("GET", fmt.Sprintf("%s?%s", u.String(), params.Encode()), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", resp.Request.Header.Get("User-Agent"))
	req.Header.Set("Referer", resp.Request.URL.String())

	log.Printf("Requesting %s?%s", u.String(), params.Encode())
	client := http.Client{
		Transport: t.upstream,
		Jar:       t.cookies,
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func evaluateJS(js string) (float64, error) {
	vm := otto.New()
	result, err := vm.Run(js)
	if err != nil {
		return 0, err
	}
	return result.ToFloat()
}

var (
	jsRegexp = regexp.MustCompile(
		`setTimeout\(function\(\){\s+(var ` +
			`s,t,o,p,b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value =.+?)\r?\n`,
	)
	jsReplace1Regexp = regexp.MustCompile(`a\.value = (.+ \+ t\.length).+`)
	jsReplace2Regexp = regexp.MustCompile(`\s{3,}[a-z](?: = |\.).+`)
	jsReplace3Regexp = regexp.MustCompile(`[\n\\']`)
)

func extractJS(body, host string) (string, error) {
	matches := jsRegexp.FindStringSubmatch(body)
	if len(matches) == 0 {
		return "", errors.New("No matching javascript found")
	}

	js := matches[1]
	js = jsReplace1Regexp.ReplaceAllString(js, "$1")
	js = jsReplace2Regexp.ReplaceAllString(js, "")

	// Strip characters that could be used to exit the string context
	// These characters are not currently used in Cloudflare's arithmetic snippet
	js = jsReplace3Regexp.ReplaceAllString(js, "")

	// replace t.length with the length of the domain
	js = strings.Replace(js, "t.length", strconv.Itoa(len(host)), -1)

	return js, nil
}

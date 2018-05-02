package scraper

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
var rua = uas[rng.Perm(len(uas))[0]]

// randomAgent returns a random user agent from those above
func randomAgent() string {
	return uas[rng.Perm(len(uas))[0]]
}

// keep user agent on redirect
func keepUserAgent(req *http.Request, via []*http.Request) error {
	req.Header.Set("User-Agent", via[0].UserAgent())
	return nil
}

// A Client is basically an http.Client that is also capable of transparently
// solving the cloudflare bot check.
type Client struct {
	*http.Client
	ua string
}

// NewClient returns a new cloudflare client.
func NewClient() *Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return NewClientJar(jar)
}

// NewClient returns a client using the provided CookieJar that is capable
// of saving cookies and performing requests that automaticall solve
// cloudflare challenges.
func NewClientJar(jar http.CookieJar) *Client {
	return &Client{
		Client: &http.Client{
			CheckRedirect: keepUserAgent,
			Jar:           jar,
		},
		ua: randomAgent(),
	}
}

// Do API of http.Client
func (c *Client) Do(r *http.Request) (*http.Response, error) {
	// ensure a safe user-agent
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", c.ua)
	}
	resp, err := c.Client.Do(r)
	if err != nil {
		return resp, err
	}
	printHeaders(resp)
	if isCloudflareCheck(resp) {
		return c.solveChallenge(resp)
	}
	return resp, err
}

// Get API of http.Client.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post API of http.Client
func (c *Client) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostForm API of http.Client
func (c *Client) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func isCloudflareCheck(resp *http.Response) bool {
	if resp.StatusCode == 503 && strings.HasPrefix(resp.Header.Get("Server"), "cloudflare") {
		return true
	}
	return false
}

var jschlRegexp = regexp.MustCompile(`name="jschl_vc" value="(\w+)"`)
var passRegexp = regexp.MustCompile(`name="pass" value="(.+?)"`)

func printHeaders(resp *http.Response) {
	log.Println("Headers:")
	for key, vals := range resp.Header {
		log.Printf("%s: %+v", key, vals)
	}
}

func (c *Client) solveChallenge(resp *http.Response) (*http.Response, error) {
	// the js client code sleeps before submitting for ~4000-5000ms, but
	// apparently this isn't long enough sometimes.
	time.Sleep(time.Second * 8)

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

	// make a new request, solving the cloudflare challenge
	req, err := http.NewRequest("GET", fmt.Sprintf("%s?%s", u.String(), params.Encode()), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Referer", resp.Request.URL.String())

	log.Printf("Requesting %s?%s", u.String(), params.Encode())
	log.Printf("Headers: %+v", req.Header)
	log.Printf("Cookies: %+v", c.Jar.Cookies(u))
	return c.Do(req)
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

// Copyright 2010 Gary Burd
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package oauth implements a subset of the OAuth client interface as defined
// in RFC 5849.
package oauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// noscape[b] is true if b should not be escaped per section 3.6 of the RFC.
var noEscape = [256]bool{
	'A': true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
	'a': true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
	'0': true, true, true, true, true, true, true, true, true, true,
	'-': true,
	'.': true,
	'_': true,
	'~': true,
}

// encode encodes string per section 3.6 of the RFC. If double is true, then
// the encoding is applied twice.
func encode(s string, double bool) []byte {
	// Compute size of result.
	m := 3
	if double {
		m = 5
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if noEscape[s[i]] {
			n += 1
		} else {
			n += m
		}
	}

	p := make([]byte, n)

	// Encode it.
	j := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if noEscape[b] {
			p[j] = b
			j += 1
		} else if double {
			p[j] = '%'
			p[j+1] = '2'
			p[j+2] = '5'
			p[j+3] = "0123456789ABCDEF"[b>>4]
			p[j+4] = "0123456789ABCDEF"[b&15]
			j += 5
		} else {
			p[j] = '%'
			p[j+1] = "0123456789ABCDEF"[b>>4]
			p[j+2] = "0123456789ABCDEF"[b&15]
			j += 3
		}
	}
	return p
}

type keyValue struct{ key, value []byte }

type byKeyValue []keyValue

func (p byKeyValue) Len() int      { return len(p) }
func (p byKeyValue) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p byKeyValue) Less(i, j int) bool {
	sgn := bytes.Compare(p[i].key, p[j].key)
	if sgn == 0 {
		sgn = bytes.Compare(p[i].value, p[j].value)
	}
	return sgn < 0
}

func (p byKeyValue) appendValues(values url.Values) byKeyValue {
	for k, vs := range values {
		k := encode(k, true)
		for _, v := range vs {
			v := encode(v, true)
			p = append(p, keyValue{k, v})
		}
	}
	return p
}

// writeBaseString writes method, url, and params to w using the OAuth signature
// base string computation described in section 3.4.1 of the RFC.
func writeBaseString(w io.Writer, method string, u *url.URL, appParams url.Values, oauthParams map[string]string) {
	// Method
	w.Write(encode(strings.ToUpper(method), false))
	w.Write([]byte{'&'})

	// URL
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	uNoQuery := *u
	uNoQuery.RawQuery = ""
	path := uNoQuery.RequestURI()

	switch {
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = host[:len(host)-len(":80")]
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = host[:len(host)-len(":443")]
	}

	w.Write(encode(scheme, false))
	w.Write(encode("://", false))
	w.Write(encode(host, false))
	w.Write(encode(path, false))
	w.Write([]byte{'&'})

	// Create sorted slice of encoded parameters. Parameter keys and values are
	// double encoded in a single step. This is safe because double encoding
	// does not change the sort order.
	queryParams := u.Query()
	p := make(byKeyValue, 0, len(appParams)+len(queryParams)+len(oauthParams))
	p = p.appendValues(appParams)
	p = p.appendValues(queryParams)
	for k, v := range oauthParams {
		p = append(p, keyValue{encode(k, true), encode(v, true)})
	}
	sort.Sort(p)

	// Write the parameters.
	encodedAmp := encode("&", false)
	encodedEqual := encode("=", false)
	sep := false
	for _, kv := range p {
		if sep {
			w.Write(encodedAmp)
		} else {
			sep = true
		}
		w.Write(kv.key)
		w.Write(encodedEqual)
		w.Write(kv.value)
	}
}

var (
	nonceLock    sync.Mutex
	nonceCounter uint64
)

// nonce returns a unique string.
func nonce() string {
	nonceLock.Lock()
	defer nonceLock.Unlock()
	if nonceCounter == 0 {
		binary.Read(rand.Reader, binary.BigEndian, &nonceCounter)
	}
	result := strconv.FormatUint(nonceCounter, 16)
	nonceCounter += 1
	return result
}

// oauthParams returns the OAuth request parameters for the given credentials,
// method, URL and application params. See
// http://tools.ietf.org/html/rfc5849#section-3.4 for more information about
// signatures.
func oauthParams(clientCredentials *Credentials, credentials *Credentials, method string, u *url.URL, appParams url.Values) map[string]string {
	oauthParams := map[string]string{
		"oauth_consumer_key":     clientCredentials.Token,
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        strconv.FormatInt(time.Now().Unix(), 10),
		"oauth_version":          "1.0",
		"oauth_nonce":            nonce(),
	}
	if credentials != nil {
		oauthParams["oauth_token"] = credentials.Token
	}
	if testingNonce != "" {
		oauthParams["oauth_nonce"] = testingNonce
	}
	if testingTimestamp != "" {
		oauthParams["oauth_timestamp"] = testingTimestamp
	}

	var key bytes.Buffer
	key.Write(encode(clientCredentials.Secret, false))
	key.WriteByte('&')
	if credentials != nil {
		key.Write(encode(credentials.Secret, false))
	}

	h := hmac.New(sha1.New, key.Bytes())
	writeBaseString(h, method, u, appParams, oauthParams)
	sum := h.Sum(nil)

	encodedSum := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(encodedSum, sum)

	oauthParams["oauth_signature"] = string(encodedSum)
	return oauthParams
}

// Client represents an OAuth client.
type Client struct {
	Credentials                   Credentials
	TemporaryCredentialRequestURI string // Also known as request token URL.
	ResourceOwnerAuthorizationURI string // Also known as authorization URL.
	TokenRequestURI               string // Also known as access token URL.
}

// Credentials represents client, temporary and token credentials.
type Credentials struct {
	Token  string // Also known as consumer key or access token.
	Secret string // Also known as consumer secret or access token secret.
}

var (
	testingTimestamp string
	testingNonce     string
)

// SignParam adds an OAuth signature to params. The urlStr must not include a query string.
//
// See http://tools.ietf.org/html/rfc5849#section-3.5.2 for
// information about transmitting OAuth parameters in a request body and
// http://tools.ietf.org/html/rfc5849#section-3.5.2 for information about
// transmitting OAuth parameters in a query string.
func (c *Client) SignParam(credentials *Credentials, method, urlStr string, params url.Values) {
	u, _ := url.Parse(urlStr)
	u.RawQuery = ""
	for k, v := range oauthParams(&c.Credentials, credentials, method, u, params) {
		params.Set(k, v)
	}
}

// AuthorizationHeader returns the HTTP authorization header value for given
// method, URL and parameters. 
//
// See http://tools.ietf.org/html/rfc5849#section-3.5.1 for information about
// transmitting OAuth parameters in an HTTP request header.
func (c *Client) AuthorizationHeader(credentials *Credentials, method string, u *url.URL, params url.Values) string {
	p := oauthParams(&c.Credentials, credentials, method, u, params)
	var buf bytes.Buffer
	buf.WriteString(`OAuth oauth_consumer_key="`)
	buf.Write(encode(p["oauth_consumer_key"], false))
	buf.WriteString(`", oauth_nonce="`)
	buf.Write(encode(p["oauth_nonce"], false))
	buf.WriteString(`", oauth_signature="`)
	buf.Write(encode(p["oauth_signature"], false))
	buf.WriteString(`", oauth_signature_method="HMAC-SHA1", oauth_timestamp="`)
	buf.Write(encode(p["oauth_timestamp"], false))
	buf.WriteString(`", oauth_token="`)
	buf.Write(encode(p["oauth_token"], false))
	buf.WriteString(`", oauth_version="1.0"`)
	return buf.String()
}

func (c *Client) request(client *http.Client, credentials *Credentials, urlStr string, params url.Values) (*Credentials, url.Values, error) {
	c.SignParam(credentials, "POST", urlStr, params)
	resp, err := client.PostForm(urlStr, params)
	if err != nil {
		return nil, nil, err
	}
	p, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("OAuth server status %d, %s", resp.StatusCode, string(p))
	}
	vals, err := url.ParseQuery(string(p))
	if err != nil {
		return nil, nil, err
	}
	credentials = &Credentials{
		Token:  vals.Get("oauth_token"),
		Secret: vals.Get("oauth_token_secret"),
	}
	if credentials.Token == "" {
		return nil, nil, errors.New("No OAuth token in server result")
	}
	if credentials.Secret == "" {
		return nil, nil, errors.New("No OAuth secret in server result")
	}
	return credentials, vals, nil
}

// RequestTemporaryCredentials requests temporary credentials from the server.
// See http://tools.ietf.org/html/rfc5849#section-2.1 for information about
// temporary credentials.
func (c *Client) RequestTemporaryCredentials(client *http.Client, callbackURL string, additionalParams url.Values) (*Credentials, error) {
	params := make(url.Values)
	for k, vs := range additionalParams {
		params[k] = vs
	}
	if callbackURL != "" {
		params.Set("oauth_callback", callbackURL)
	}
	credentials, _, err := c.request(client, nil, c.TemporaryCredentialRequestURI, params)
	return credentials, err
}

// RequestToken requests token credentials from the server. See
// http://tools.ietf.org/html/rfc5849#section-2.3 for information about token
// credentials.
func (c *Client) RequestToken(client *http.Client, temporaryCredentials *Credentials, verifier string) (*Credentials, url.Values, error) {
	params := make(url.Values)
	if verifier != "" {
		params.Set("oauth_verifier", verifier)
	}
	credentials, vals, err := c.request(client, temporaryCredentials, c.TokenRequestURI, params)
	if err != nil {
		return nil, nil, err
	}
	return credentials, vals, nil
}

// AuthorizationURL returns the URL for resource owner authorization. See
// http://tools.ietf.org/html/rfc5849#section-2.2 for information about
// resource owner authorization.
func (c *Client) AuthorizationURL(temporaryCredentials *Credentials, additionalParams url.Values) string {
	params := make(url.Values)
	for k, vs := range additionalParams {
		params[k] = vs
	}
	params.Set("oauth_token", temporaryCredentials.Token)
	return c.ResourceOwnerAuthorizationURI + "?" + params.Encode()
}

type transport struct {
	client      *Client
	credentials *Credentials
	transport   http.RoundTripper
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	var params url.Values
	if ct := r.Header.Get("Content-Type"); ct == "application/x-www-form-urlencoded" {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		params, err = url.ParseQuery(string(b))
		if err != nil {
			return nil, err
		}
		r.Body = struct {
			io.Reader
			io.Closer
		}{bytes.NewReader(b), r.Body}
	}
	h := make(http.Header)
	for k, vs := range r.Header {
		h[k] = vs
	}
	h.Set("Authorization", t.client.AuthorizationHeader(t.credentials, r.Method, r.URL, params))
	r.Header = h
	return t.transport.RoundTrip(r)
}

// Transport wraps baseTransport with request signing. Because the returned
// transport must buffer and parse the request body, it is more efficient to
// use SignParam or AuthorizationHeader directly.
func (c *Client) HTTPTransport(credentials *Credentials, baseTransport http.RoundTripper) http.RoundTripper {
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	return &transport{client: c, credentials: credentials, transport: baseTransport}
}

// Client returns a copy of baseClient with the transport set to a signing
// wrapper around baseClient's transport.
func (c *Client) HTTPClient(credentials *Credentials, baseClient *http.Client) *http.Client {
	if baseClient == nil {
		baseClient = http.DefaultClient
	}
	client := *baseClient
	client.Transport = c.HTTPTransport(credentials, baseClient.Transport)
	return &client
}

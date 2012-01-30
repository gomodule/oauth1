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
// in RFC 5849 (http://tools.ietf.org/html/rfc5849).
//
// This package assumes that the application writes request URL paths to the
// network using the encoding implemented by the net/url URL RequestURI method.
// The HTTP client in the standard net/http package uses this encoding.
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
	"regexp"
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

var urlPat = regexp.MustCompile("^([^:]+)://([^:/]+)(:[0-9]+)?(.*)$")

// writeBaseString writes method, url, and params to w using the OAuth signature
// base string computation described in section 3.4.1 of the RFC.
func writeBaseString(w io.Writer, method string, urlStr string, params url.Values) {
	// Method
	w.Write(encode(strings.ToUpper(method), false))
	w.Write([]byte{'&'})

	// URL
	u, _ := url.Parse(urlStr)
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	path := u.RequestURI()
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

	// Create sorted array of encoded parameters. Parameter keys and values are
	// double encoded in a single step. This is safe to do because double
	// encoding does not change the sort order.
	p := make([]keyValue, 0, len(params))
	for key, values := range params {
		encodedKey := encode(key, true)
		for _, value := range values {
			p = append(p, keyValue{encodedKey, encode(value, true)})
		}
	}
	sort.Sort(byKeyValue(p))

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

// signature returns the OAuth signature  for the given credentials, method,
// URL and params. See http://tools.ietf.org/html/rfc5849#section-3.4 for more
// information about signatures.
func signature(clientCredentials *Credentials, credentials *Credentials, method, urlStr string, params url.Values) string {
	var key bytes.Buffer

	key.Write(encode(clientCredentials.Secret, false))
	key.WriteByte('&')
	if credentials != nil {
		key.Write(encode(credentials.Secret, false))
	}

	h := hmac.New(sha1.New, key.Bytes())
	writeBaseString(h, method, urlStr, params)
	sum := h.Sum(nil)

	encodedSum := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(encodedSum, sum)
	return string(encodedSum)
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

// Client represents an OAuth client.
type Client struct {
	Credentials                   Credentials
	TemporaryCredentialRequestURI string // Also known as request token URL.
	ResourceOwnerAuthorizationURI string // Also known as authorization URL.
	TokenRequestURI               string // Also known as access token URL
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

// SignParam adds an OAuth signature to params See
// http://tools.ietf.org/html/rfc5849#section-3.5.2 for information about
// transmitting OAuth parameters in a request body and
// http://tools.ietf.org/html/rfc5849#section-3.5.2 for information about
// transmitting OAuth parameters in a query string.
func (c *Client) SignParam(credentials *Credentials, method, urlStr string, params url.Values) {
	params.Set("oauth_consumer_key", c.Credentials.Token)
	params.Set("oauth_signature_method", "HMAC-SHA1")
	params.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	params.Set("oauth_version", "1.0")
	if testingNonce == "" {
		params.Set("oauth_nonce", nonce())
	} else {
		params.Set("oauth_nonce", testingNonce)
	}
	if testingTimestamp == "" {
		params.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	} else {
		params.Set("oauth_timestamp", testingTimestamp)
	}
	if credentials != nil {
		params.Set("oauth_token", credentials.Token)
	}
	params.Set("oauth_signature", signature(&c.Credentials, credentials, method, urlStr, params))
}

// AuthorizationHeader returns the HTTP authorization header value for given
// method, URL and parameters. See
// http://tools.ietf.org/html/rfc5849#section-3.5.1 for information about
// transmitting OAuth parameters in an HTTP request header.
func (c *Client) AuthorizationHeader(credentials *Credentials, method, urlStr string, params url.Values) string {
	// Don't scribble on caller's params. 
	p := make(url.Values)
	for k, v := range params {
		p[k] = v
	}
	c.SignParam(credentials, method, urlStr, p)
	var buf bytes.Buffer
	buf.WriteString(`OAuth oauth_consumer_key="`)
	buf.Write(encode(p["oauth_consumer_key"][0], false))
	buf.WriteString(`", oauth_nonce="`)
	buf.Write(encode(p["oauth_nonce"][0], false))
	buf.WriteString(`", oauth_signature="`)
	buf.Write(encode(p["oauth_signature"][0], false))
	buf.WriteString(`", oauth_timestamp="`)
	buf.Write(encode(p["oauth_timestamp"][0], false))
	buf.WriteString(`", oauth_token="`)
	buf.Write(encode(p["oauth_token"][0], false))
	buf.WriteString(`", oauth_signature_method="HMAC-SHA1", oauth_version="1.0"`)
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

// AuthorizationURL returns the URL for resource owner authorization.  See
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

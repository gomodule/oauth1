// Copyright 2011 Gary Burd
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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/garyburd/go-oauth/oauth"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"
)

var (
	oauthClient = oauth.Client{
		TemporaryCredentialRequestURI: "http://api.twitter.com/oauth/request_token",
		ResourceOwnerAuthorizationURI: "http://api.twitter.com/oauth/authenticate",
		TokenRequestURI:               "http://api.twitter.com/oauth/access_token",
	}

	config = struct {
		Credentials *oauth.Credentials
	}{
		&oauthClient.Credentials,
	}

	configPath = flag.String("config", "config.json", "Path to configuration file")
	httpAddr   = flag.String("addr", ":8080", "HTTP server address")
	sign       = flag.String("sign", "SignParam", "'SignParam' or 'Form'")
)

// readConfiguration reads the configuration file from the path specified by
// the config command line flag.
func readConfiguration() error {
	b, err := ioutil.ReadFile(*configPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &config)
}

// addCookie adds a cookie to the response. The cookie value is the base64
// encoding of the json encoding of data. If data is nil, then the cookie is
// deleted. 
func addCookie(w http.ResponseWriter, name string, data interface{}, maxAge time.Duration) error {
	c := http.Cookie{
		Name:     name,
		Path:     "/",
		HttpOnly: true,
	}
	if data == nil {
		maxAge = -10000 * time.Second
	} else {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(data); err != nil {
			return err
		}
		c.Value = base64.URLEncoding.EncodeToString(b.Bytes())
	}
	if maxAge != 0 {
		c.MaxAge = int(maxAge / time.Second)
		c.Expires = time.Now().Add(maxAge)
	}
	http.SetCookie(w, &c)
	return nil
}

// getCookie gets a base64 and json encoded value from a cookie.  
func getCookie(r *http.Request, name string, value interface{}) error {
	c, err := r.Cookie(name)
	if err != nil {
		return err
	}
	return json.NewDecoder(base64.NewDecoder(base64.URLEncoding, strings.NewReader(c.Value))).Decode(value)
}

// decodeResponse decodes the JSON response from the Twitter API.
func decodeResponse(resp *http.Response, data interface{}) error {
	if resp.StatusCode != 200 {
		p, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Get %s returned status %d, %s", resp.Request.URL, resp.StatusCode, p)
	}
	return json.NewDecoder(resp.Body).Decode(data)
}

// getTwitter gets a resource from the Twitter API and decodes the JSON response to data. 
var getTwitter func(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error

func getTwitterSignParam(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error {
	if form == nil {
		form = make(url.Values)
	}
	oauthClient.SignParam(cred, "GET", urlStr, form)
	resp, err := http.Get(urlStr + "?" + form.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, data)
}

func getTwitterForm(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error {
	resp, err := oauthClient.Get(http.DefaultClient, cred, urlStr, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, data)
}

// postTwitter posts to the Twitter API and decodes the JSON response to data. 
var postTwitter func(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error

func postTwitterSignParam(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error {
	oauthClient.SignParam(cred, "POST", urlStr, form)
	resp, err := http.PostForm(urlStr, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, data)
}

func postTwitterForm(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error {
	resp, err := oauthClient.Post(http.DefaultClient, cred, urlStr, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, data)
}

// respond responds to a request by executing the html template t with data.
func respond(w http.ResponseWriter, t *template.Template, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Print(err)
	}
}

// serveLogin gets the OAuth temp credentials and redirects the user the
// OAuth server's authorization page.
func serveLogin(w http.ResponseWriter, r *http.Request) {
	callback := "http://" + r.Host + "/callback"
	tempCred, err := oauthClient.RequestTemporaryCredentials(http.DefaultClient, callback, nil)
	if err != nil {
		http.Error(w, "Error getting temp cred, "+err.Error(), 500)
		return
	}
	addCookie(w, "temp", tempCred.Secret, 0)
	http.Redirect(w, r, oauthClient.AuthorizationURL(tempCred, nil), 302)
}

// serveOAuthCallback handles callbacks from the OAuth server.
func serveOAuthCallback(w http.ResponseWriter, r *http.Request) {
	tempCred := oauth.Credentials{
		Token: r.FormValue("oauth_token"),
	}
	if err := getCookie(r, "temp", &tempCred.Secret); err != nil {
		http.Error(w, "Error getting temp token secret from cookie, "+err.Error(), 500)
		return
	}
	tokenCred, _, err := oauthClient.RequestToken(http.DefaultClient, &tempCred, r.FormValue("oauth_verifier"))
	if err != nil {
		http.Error(w, "Error getting request token, "+err.Error(), 500)
		return
	}
	addCookie(w, "twitter", tokenCred, 24*time.Hour)
	http.Redirect(w, r, "/", 302)
}

func serveLogout(w http.ResponseWriter, r *http.Request) {
	addCookie(w, "twitter", nil, 0)
	http.Redirect(w, r, "/", 302)
}

// authHandler reads the auth cookie and invokes a handler with the result.
type authHandler struct {
	handler  func(w http.ResponseWriter, r *http.Request, c *oauth.Credentials)
	optional bool
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var cred oauth.Credentials
	if err := getCookie(r, "twitter", &cred); err != nil {
		if err != http.ErrNoCookie {
			http.Error(w, "Error reading auth cookie, "+err.Error(), 500)
			return
		}
		cred.Token = ""
	}

	var pcred *oauth.Credentials
	if cred.Token != "" && cred.Secret != "" {
		pcred = &cred
	}

	if pcred == nil && !h.optional {
		http.Error(w, "Not logged in.", 403)
		return
	}

	h.handler(w, r, pcred)
}

func serveHome(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if cred == nil {
		respond(w, homeLoggedOutTmpl, nil)
	} else {
		respond(w, homeTmpl, nil)
	}
}

func serveTimeline(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {
	var timeline []map[string]interface{}
	if err := getTwitter(
		cred,
		"http://api.twitter.com/1/statuses/home_timeline.json",
		nil,
		&timeline); err != nil {
		http.Error(w, "Error getting timeline, "+err.Error(), 500)
		return
	}
	respond(w, timelineTmpl, timeline)
}

func serveMessages(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {
	var dms []map[string]interface{}
	if err := getTwitter(
		cred,
		"http://api.twitter.com/1/direct_messages.json",
		nil,
		&dms); err != nil {
		http.Error(w, "Error getting timeline, "+err.Error(), 500)
		return
	}
	respond(w, messagesTmpl, dms)
}

func serveFollow(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {
	var profile map[string]interface{}
	if err := postTwitter(
		cred,
		"https://api.twitter.com/1.1/friendships/create.json",
		url.Values{"screen_name": {"gburd"}, "follow": {"true"}},
		&profile); err != nil {
		http.Error(w, "Error following, "+err.Error(), 500)
		return
	}
	respond(w, followTmpl, profile)
}

func main() {
	flag.Parse()
	if err := readConfiguration(); err != nil {
		log.Fatalf("Error reading configuration, %v", err)
	}

	// This application demonstrates different ways to use the oauth Client to
	// sign requests. A real application only needs to sign requests one way.
	// Do not copy the following switch statement to your application.
	switch *sign {
	case "SignParam":
		getTwitter = getTwitterSignParam
		postTwitter = postTwitterSignParam
	case "Form":
		getTwitter = getTwitterForm
		postTwitter = postTwitterForm
	default:
		log.Fatalf("bad valud for sign flag, %q", *sign)
	}

	http.Handle("/", &authHandler{handler: serveHome, optional: true})
	http.Handle("/timeline", &authHandler{handler: serveTimeline})
	http.Handle("/messages", &authHandler{handler: serveMessages})
	http.Handle("/follow", &authHandler{handler: serveFollow})
	http.HandleFunc("/login", serveLogin)
	http.HandleFunc("/logout", serveLogout)
	http.HandleFunc("/callback", serveOAuthCallback)
	if err := http.ListenAndServe(*httpAddr, nil); err != nil {
		log.Fatalf("Error listening, %v", err)
	}
}

var (
	homeLoggedOutTmpl = template.Must(template.New("loggedout").Parse(
		`<html>
<head>
</head>
<body>
<a href="/login"><img src="http://a0.twimg.com/images/dev/buttons/sign-in-with-twitter-d.png"></a>
</body>
</html>`))

	homeTmpl = template.Must(template.New("home").Parse(
		`<html>
<head>
</head>
<body>
<p><a href="/timeline">timeline</a>
<p><a href="/messages">direct messages</a>
<p><a href="/follow">follow @gburd</a>
<p><a href="/logout">logout</a>
</body></html>`))

	messagesTmpl = template.Must(template.New("messages").Parse(
		`<html>
<head>
</head>
<body>
<p><a href="/">home</a>
{{range .}}
<p><b>{{html .sender.name}}</b> {{html .text}}
{{end}}
</body></html>`))

	timelineTmpl = template.Must(template.New("timeline").Parse(
		`<html>
<head>
</head>
<body>
<p><a href="/">home</a>
{{range .}}
<p><b>{{html .user.name}}</b> {{html .text}}
{{end}}
</body></html>`))

	followTmpl = template.Must(template.New("follow").Parse(
		`<html>
<head>
</head>
<body>
<p><a href="/">home</a>
<p>You are now following <a href="https://twitter.com/{{html .screen_name}}">{{html .name}}</a>
</body></html>`))
)

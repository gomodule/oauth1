// Copyright 2013 Gary Burd
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
	"encoding/json"
	"flag"
	"fmt"
	"github.com/garyburd/go-oauth/oauth"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sync"
	"text/template"
	"time"
)

var oauthClient = oauth.Client{
	TemporaryCredentialRequestURI: "http://api-public.netflix.com/oauth/request_token",
	ResourceOwnerAuthorizationURI: "http://api-user.netflix.com/oauth/login",
	TokenRequestURI:               "http://api-public.netflix.com/oauth/access_token",
}

var credPath = flag.String("config", "config.json", "Path to configuration file containing the application's credentials.")

func readCredentials() error {
	b, err := ioutil.ReadFile(*credPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &oauthClient.Credentials)
}

var (
	// secrets maps credential tokens to credential secrets. A real application
	// will use a database to store credentials.
	secretsMutex sync.Mutex
	secrets      = map[string]string{}
)

func putCredentials(cred *oauth.Credentials) {
	secretsMutex.Lock()
	defer secretsMutex.Unlock()
	secrets[cred.Token] = cred.Secret
}

func getCredentials(token string) *oauth.Credentials {
	secretsMutex.Lock()
	defer secretsMutex.Unlock()
	if secret, ok := secrets[token]; ok {
		return &oauth.Credentials{Token: token, Secret: secret}
	}
	return nil
}

func deleteCredentials(token string) {
	secretsMutex.Lock()
	defer secretsMutex.Unlock()
	delete(secrets, token)
}

// serveLogin gets the OAuth temp credentials and redirects the user to the
// OAuth server's authorization page.
func serveLogin(w http.ResponseWriter, r *http.Request) {
	callback := "http://" + r.Host + "/callback"
	tempCred, err := oauthClient.RequestTemporaryCredentials(http.DefaultClient, "", nil)
	if err != nil {
		http.Error(w, "Error getting temp cred, "+err.Error(), 500)
		return
	}
	putCredentials(tempCred)

	// Netflix uses the older version of OAuth where the callback URL is passed
	// to the server in the redirect URL query string. Netflix also expectes to
	// find the client token in the redirectURL query string.
	params := url.Values{
		"oauth_callback":     {callback},
		"oauth_consumer_key": {oauthClient.Credentials.Token},
	}
	http.Redirect(w, r, oauthClient.AuthorizationURL(tempCred, params), 302)
}

// serveOAuthCallback handles callbacks from the OAuth server.
func serveOAuthCallback(w http.ResponseWriter, r *http.Request) {
	tempCred := getCredentials(r.FormValue("oauth_token"))
	if tempCred == nil {
		http.Error(w, "Unknown oauth_token.", 500)
		return
	}
	deleteCredentials(tempCred.Token)
	tokenCred, _, err := oauthClient.RequestToken(http.DefaultClient, tempCred, r.FormValue("oauth_verifier"))
	if err != nil {
		http.Error(w, "Error getting request token, "+err.Error(), 500)
		return
	}
	putCredentials(tokenCred)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Path:     "/",
		HttpOnly: true,
		Value:    tokenCred.Token,
	})
	http.Redirect(w, r, "/", 302)
}

// serveLogout clears the authentication cookie.
func serveLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-1 * time.Hour),
	})
	http.Redirect(w, r, "/", 302)
}

// authHandler reads the auth cookie and invokes a handler with the result.
type authHandler struct {
	handler  func(w http.ResponseWriter, r *http.Request, c *oauth.Credentials)
	optional bool
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var cred *oauth.Credentials
	if c, _ := r.Cookie("auth"); c != nil {
		cred = getCredentials(c.Value)
	}
	if cred == nil && !h.optional {
		http.Error(w, "Not logged in.", 403)
		return
	}
	h.handler(w, r, cred)
}

// apiGet issues a GET request to the Netflix API and decodes the response JSON to data.
func apiGet(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error {
	resp, err := oauthClient.Get(http.DefaultClient, cred, urlStr, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, data)
}

// apiPost issues a POST request to the Netflix API and decodes the response JSON to data.
func apiPost(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error {
	resp, err := oauthClient.Post(http.DefaultClient, cred, urlStr, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, data)
}

// decodeResponse decodes the JSON response from the Netflix API.
func decodeResponse(resp *http.Response, data interface{}) error {
	if resp.StatusCode != 200 {
		p, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("get %s returned status %d, %s", resp.Request.URL, resp.StatusCode, p)
	}
	return json.NewDecoder(resp.Body).Decode(data)
}

// respond responds to a request by executing the html template t with data.
func respond(w http.ResponseWriter, t *template.Template, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Print(err)
	}
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

func serveCurrentUser(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {
	resp, err := oauthClient.Get(http.DefaultClient, cred, "http://api-public.netflix.com/users/current", nil)
	if err != nil {
		http.Error(w, "Error getting current user, "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, resp.Body)
}

func serveCatalogTitles(w http.ResponseWriter, r *http.Request) {
	resp, err := oauthClient.Get(
		http.DefaultClient,
		nil, // nil client signature only.
		"http://api-public.netflix.com/catalog/titles",
		url.Values{"term": {"koyaanisqatsi"}})
	if err != nil {
		http.Error(w, "Error getting catalog title, "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, resp.Body)
}

var httpAddr = flag.String("addr", ":8080", "HTTP server address")

func main() {
	flag.Parse()
	if err := readCredentials(); err != nil {
		log.Fatalf("Error reading configuration, %v", err)
	}

	http.Handle("/", &authHandler{handler: serveHome, optional: true})
	http.Handle("/currentUser", &authHandler{handler: serveCurrentUser})
	http.Handle("/catalogTitles", http.HandlerFunc(serveCatalogTitles))
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
<p><a href="/login">login</a>
<p><a href="/catalogTitles">catalog titles</a> (signed request example)
</body>
</html>`))

	homeTmpl = template.Must(template.New("home").Parse(
		`<html>
<head>
</head>
<body>
<p><a href="/currentUser">current user</a> (protected request example)
<p><a href="/catalogTitles">catalog titles</a> (signed request example)
<p><a href="/logout">logout</a>
</body></html>`))
)

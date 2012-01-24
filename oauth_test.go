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

package oauth

import (
	"bytes"
	"net/url"
	"testing"
)

var signatureTests = []struct {
	method            string
	url               string
	params            url.Values
	base              string
	clientCredentials Credentials
	credentials       Credentials
	sig               string
}{
	{
		"GeT",
		"hTtp://pHotos.example.net/photos",
		url.Values{
			"oauth_consumer_key":     {"dpf43f3p2l4k3l03"},
			"oauth_token":            {"nnch734d00sl2jdk"},
			"oauth_nonce":            {"kllo9940pd9333jh"},
			"oauth_timestamp":        {"1191242096"},
			"oauth_signature_method": {"HMAC-SHA1"},
			"oauth_version":          {"1.0"},
			"size":                   {"original"},
			"file":                   {"vacation.jpg"},
		},
		"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
		Credentials{"dpf43f3p2l4k3l03", "kd94hf93k423kf44"},
		Credentials{"kd94hf93k423kf44", "pfkkdhi9sl3r4s00"},
		"tR3+Ty81lMeYAr/Fid0kMTYa/WM="},
	{
		"GET",
		"http://PHOTOS.example.net:8001/Photos",
		url.Values{
			"oauth_consumer_key":     {"dpf43f3++p+#2l4k3l03"},
			"oauth_token":            {"nnch734d(0)0sl2jdk"},
			"oauth_nonce":            {"kllo~9940~pd9333jh"},
			"oauth_timestamp":        {"1191242096"},
			"oauth_signature_method": {"HMAC-SHA1"},
			"oauth_version":          {"1.0"},
			"photo size":             {"300%"},
			"title":                  {"Back of $100 Dollars Bill"},
		},
		"GET&http%3A%2F%2Fphotos.example.net%3A8001%2FPhotos&oauth_consumer_key%3Ddpf43f3%252B%252Bp%252B%25232l4k3l03%26oauth_nonce%3Dkllo~9940~pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d%25280%25290sl2jdk%26oauth_version%3D1.0%26photo%2520size%3D300%2525%26title%3DBack%2520of%2520%2524100%2520Dollars%2520Bill",
		Credentials{"dpf43f3++p+#2l4k3l03", "kd9@4h%%4f93k423kf44"},
		Credentials{"nnch734d(0)0sl2jdk", "pfkkd#hi9_sl-3r=4s00"},
		"tTFyqivhutHiglPvmyilZlHm5Uk="},
	{
		"GET",
		"http://EXAMPLE.COM:80/Space%20Craft",
		url.Values{
			"oauth_consumer_key":     {"abcd"},
			"oauth_token":            {"ijkl"},
			"oauth_nonce":            {"Ix4U1Ei3RFL"},
			"oauth_timestamp":        {"1327384901"},
			"oauth_signature_method": {"HMAC-SHA1"},
			"oauth_version":          {"1.0"},
			"name":                   {"value", "value"},
		},
		"GET&http%3A%2F%2Fexample.com%2FSpace%2520Craft&name%3Dvalue%26name%3Dvalue%26oauth_consumer_key%3Dabcd%26oauth_nonce%3DIx4U1Ei3RFL%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1327384901%26oauth_token%3Dijkl%26oauth_version%3D1.0",
		Credentials{"abcd", "efgh"},
		Credentials{"ijkl", "mnop"},
		"TZZ5u7qQorLnmKs+iqunb8gqkh4="},
	{
		"GET",
		"https://hello:443/world",
		url.Values{
			"oauth_consumer_key":     {"abcd"},
			"oauth_token":            {"ijkl"},
			"oauth_nonce":            {"Ix4U1Ei3RFL"},
			"oauth_timestamp":        {"1327384901"},
			"oauth_signature_method": {"HMAC-SHA1"},
			"oauth_version":          {"1.0"},
		},
		"GET&https%3A%2F%2Fhello%2Fworld&oauth_consumer_key%3Dabcd%26oauth_nonce%3DIx4U1Ei3RFL%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1327384901%26oauth_token%3Dijkl%26oauth_version%3D1.0",
		Credentials{"abcd", "efgh"},
		Credentials{"ijkl", "mnop"},
		"elVM7oxG5dFpjuXXHTJsb/G75cY="},
}

func TestSignature(t *testing.T) {
	for _, st := range signatureTests {
		var buf bytes.Buffer
		writeBaseString(&buf, st.method, st.url, st.params)
		base := buf.String()
		if base != st.base {
			t.Errorf("base string for %s %s\n    = %q,\n want %q", st.method, st.url, base, st.base)
		}
		sig := signature(&st.clientCredentials, &st.credentials, st.method, st.url, st.params)
		if sig != st.sig {
			t.Errorf("signature for %s %s = %q, want %q", st.method, st.url, sig, st.sig)
		}
	}
}

func TestHeader(t *testing.T) {
	// All values in this test were taken from Twitter's OAuth tool.

	client := Client{
		Credentials: Credentials{
			Token:  "3NNCZTHoBoSSk1V4cPCZA",
			Secret: "pHT9O4hvqH8mwe1JB224BQ4iv9cXPE11m9n90n0EY",
		},
	}
	token := Credentials{
		Token:  "10212-JJ3Zc1A49qSMgdcAO2GMOpW9l7A348ESmhjmOBOU",
		Secret: "yF75mvq4LZMHj9O0DXwoC3ZxUnN1ptvieThYuOAYM",
	}
	urlStr := "https://api.twitter.com/1/direct_messages.json"
	params := url.Values{"count": {"10"}}

	testingTimestamp = "1323729189"
	testingNonce = "8e51932665a8e33c54e8872f09b661b8"
	actualHeader := client.AuthorizationHeader(&token, "GET", urlStr, params)
	testingTimestamp = ""
	testingNonce = ""

	expectedHeader := `OAuth ` +
		`oauth_consumer_key="3NNCZTHoBoSSk1V4cPCZA", ` +
		`oauth_nonce="8e51932665a8e33c54e8872f09b661b8", ` +
		`oauth_signature="13tM5UUxbPrRZjeCGWgl3yUuUNA%3D", ` +
		`oauth_timestamp="1323729189", ` +
		`oauth_token="10212-JJ3Zc1A49qSMgdcAO2GMOpW9l7A348ESmhjmOBOU", ` +
		`oauth_signature_method="HMAC-SHA1", ` +
		`oauth_version="1.0"`

	if actualHeader != expectedHeader {
		t.Errorf("Header mismatch, \ngot:  %s\nwant: %s", actualHeader, expectedHeader)
	}
}

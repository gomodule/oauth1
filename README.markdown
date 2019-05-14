# OAuth1

[![GoDoc](https://godoc.org/github.com/gomodule/oauth1/oauth?status.svg)](https://godoc.org/github.com/gomodule/oauth1/oauth)
[![Build Status](https://travis-ci.org/gomodule/oauth1.svg?branch=master)](https://travis-ci.org/gomodule/oauth1)

OAuth1 is a [Go](https://golang.org/) client for the OAuth 1.0, OAuth 1.0a and [RFC 5849](https://tools.ietf.org/html/rfc5849) Protocols.
The package supports the following signatures:
* HMAC-SHA1
* HMAC-SHA256
* RSA-SHA1
* PLAINTEXT


## Installation

```bash
$ go get -u github.com/gomodule/oauth1/oauth
```  
  
Import it in your code:
    
```go
import "github.com/gomodule/oauth1/oauth"
```

### Prerequisite

`oauth1` uses the context package requiring Go 1.7 or later.

## License

`oauth1` is available under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html).

## Documentation
    
- [Reference](http://godoc.org/github.com/gomodule/oauth1/oauth)
- Examples
    - [Discogs](https://github.com/gomodule/oauth1/tree/master/examples/discogs)
    - [Dropbox](https://github.com/gomodule/oauth1/tree/master/examples/dropbox)
    - [Quickbooks](https://github.com/gomodule/oauth1/tree/master/examples/quickbooks)
    - [SmugMug](https://github.com/gomodule/oauth1/tree/master/examples/smugmug)
    - [Twitter on App Engine](https://github.com/gomodule/oauth1/tree/master/examples/appengine) 
    - [Twitter](https://github.com/gomodule/oauth1/tree/master/examples/twitter) 
    - [Twitter OOB](https://github.com/gomodule/oauth1/tree/master/examples/twitteroob) (a command line application using OOB authorization)
    - [Yelp](https://github.com/gomodule/oauth1/tree/master/examples/yelp)

package api

import (
	"log"
	"net/http"
	"net/http/httputil"
	url2 "net/url"
	"os"
	"time"
)

func GetProxyUrl() *url2.URL {
	parse, err := url2.Parse(os.Getenv("PROXY_URL"))
	if err != nil {
		panic(err)
	}
	return parse
}

// Handle Serverless Func
func Handle(w http.ResponseWriter, r *http.Request) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var start = time.Now()
	defer func() {
		log.Printf("method: %s path:%s remote:%s spent:%v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	}()
	httputil.NewSingleHostReverseProxy(GetProxyUrl()).ServeHTTP(w, r)
}

package api

import (
	"io"
	"log"
	"net/http"
	url2 "net/url"
	"os"
	"strings"
	"time"
)

func GetOrigin() string {
	return os.Getenv("Origin")
}

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
	request, err := http.NewRequest(r.Method, "", r.Body)
	if err != nil {
		panic(err)
	}
	for k, v := range r.Header {
		request.Header[k] = v
	}
	request.URL = GetProxyUrl().ResolveReference(r.URL)
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Println(err)
		http.Error(w, "unknown err", 500)
		return
	}
	for k, v := range resp.Header {
		w.Header().Set(k, strings.Join(v, "; "))
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println(err)
	}
}

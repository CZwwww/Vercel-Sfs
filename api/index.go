package api

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
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
	dumpRequest, err2 := httputil.DumpRequest(r, false)
	if err2 != nil {
		log.Println(err2)
		return
	}
	log.Println("\n"+string(dumpRequest))
	if isWebSock(r) {
		handleWebSocket(w, r)
		return
	}
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

func isWebSock(r *http.Request) bool {
	if r.Header.Get("Sec-Websocket-Key") != "" {
		return true
	}
	return false
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	host := GetProxyUrl().Host
	controller := http.NewResponseController(w)
	request, err2 := httputil.DumpRequest(r, false)
	if err2 != nil {
		panic(err2)
	}
	hijack, _, err := controller.Hijack()
	if err != nil {
		panic(err)
	}
	defer hijack.Close()
	dial, err := net.Dial("tcp", host)
	if err != nil {
		panic(err)
	}
	defer dial.Close()
	log.Println("\n" + string(request))
	log.Println(request[len(request)-4:])
	request = append(request, []byte("Connection: Upgrade\r\nUpgrade: websocket\r\n")...)
	_, err2 = dial.Write(request)
	if err2 != nil {
		panic(err2)
	}
	go func() {
		_, err2 := io.Copy(hijack, dial)
		if err2 != nil {
			log.Println(err2)
		}
	}()
	_, err = io.Copy(dial, hijack)
	if err != nil {
		log.Println(err)
	}
}

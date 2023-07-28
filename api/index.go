package api

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

var needReplace []string

func init() {
	getenv := os.Getenv("URL_REPLACE")
	needReplace = strings.Split(getenv, ";")
}

const (
	DEBUG = iota
)

func GetProxyUrl(env int, url string) string {
	switch env {
	case DEBUG:
		return url
	default:
		return os.Getenv("PROXY_URL")
	}
}

// Handle Serverless Func
func Handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("method: %s path:%s query:%v remote:%s", r.Method, r.RequestURI, r.URL.Query(), r.RemoteAddr)
	log.Printf("%+v", *r.URL)
	r.URL.Query()
	var start = time.Now()
	defer func() {
		log.Printf("method: %s path:%s remote:%s spent:%v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	}()
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		ao := os.Getenv("Allow-Origin")
		ah := os.Getenv("Allow-Headers")
		if ao != "" {
			w.Header().Set("Access-Control-Allow-Origin", ao)
		}
		if ah != "" {
			w.Header().Set("Access-Control-Allow-Headers", ah)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	err := r.ParseMultipartForm(1024 * 1024 * 64)
	if err != nil {
		//log.Println(err)
	}
	var mode = 99
	//DEBUG
	//mode = DEBUG
	urlStr := GetProxyUrl(mode, "http://localhost:34555/")
	parse, err := url.Parse(urlStr)
	if err != nil {
		write503(w, err)
		return
	}
	log.Println(r.URL.RawQuery)
	//log.Println(parse.Opaque)
	var rawQuery string
	if r.URL.RawQuery != "" {
		rawQuery = "?" + r.URL.RawQuery
	}
	var proxyUrl = parse.Scheme + "://" + path.Clean(strings.TrimPrefix(path.Join(parse.Host, r.URL.Path+rawQuery), "/"))
	log.Printf("proxyUrl: %s", proxyUrl)
	all, err := io.ReadAll(r.Body)
	if err != nil {
		write503(w, err)
		return
	}
	log.Println(string(all))
	log.Println(r.PostForm)
	var request *http.Request
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/x-www-form-urlencoded" {
		request, err = http.NewRequest(r.Method, proxyUrl, strings.NewReader(r.PostForm.Encode()))
	} else if strings.Contains(contentType, "multipart") {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		value := r.MultipartForm.Value
		for k, v := range value {
			for _, s := range v {
				err := writer.WriteField(k, s)
				if err != nil {
					write503(w, err)
					return
				}
			}
		}
		for s, headers := range r.MultipartForm.File {
			for _, header := range headers {
				file, err := writer.CreateFormFile(s, header.Filename)
				if err != nil {
					write503(w, err)
					return
				}
				open, err := header.Open()
				if err != nil {
					write503(w, err)
					return
				}
				_, err = io.Copy(file, open)
				if err != nil {
					write503(w, err)
					return
				}
			}
		}
		writer.Close()
		contentType = writer.FormDataContentType()
		request, err = http.NewRequest(r.Method, proxyUrl, &buf)
	} else {
		request, err = http.NewRequest(r.Method, proxyUrl, bytes.NewReader(all))
	}
	if err != nil {
		write503(w, err)
		return
	}
	request.Header = r.Header.Clone()
	request.Header.Set("Content-Type", contentType)
	request.Form = r.Form
	log.Println(r.Form)
	request.MultipartForm = r.MultipartForm
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		write503(w, err)
		return
	}
	for s, vs := range resp.Header {
		if !corsIncludes(s) {
			w.Header().Add(s, strings.Join(vs, "; "))
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	ao := os.Getenv("Allow-Origin")
	ah := os.Getenv("Allow-Headers")
	if ao != "" {
		w.Header().Set("Access-Control-Allow-Origin", ao)
	}
	if ah != "" {
		w.Header().Set("Access-Control-Allow-Headers", ah)
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println(err)
	}
}

func corsIncludes(headerKey string) bool {
	switch headerKey {
	case "Cross-Origin-Opener-Policy":
		return true
	case "Access-Control-Allow-Origin":
		return true
	default:
		return false
	}
}

func write503(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(err.Error()))
}

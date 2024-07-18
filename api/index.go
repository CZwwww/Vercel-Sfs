package api

import (
	"bytes"
	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/rand"
	// "encoding/base64"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
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
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("method: %s path:%s query:%v remote:%s", r.Method, r.RequestURI, r.URL.Query(), r.RemoteAddr)
	log.Printf("%+v", *r.URL)
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
	log.Println(r.URL.Path)
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
		values := url.Values{}
		for s, i := range r.PostForm {
			for _, s2 := range i {
				encrypt, err := Encrypt([]byte(s2), GetAesKey())
				if err != nil {
					write503(w, err)
				}
				values.Add(s, encrypt)
			}
		}
		request, err = http.NewRequest(r.Method, proxyUrl, strings.NewReader(values.Encode()))
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
		encrypt, err := Encrypt(all, GetAesKey())
		if err != nil {
			write503(w, err)
			return
		}
		request, err = http.NewRequest(r.Method, proxyUrl, strings.NewReader(encrypt))
	}
	if err != nil {
		write503(w, err)
		return
	}
	request.Header = r.Header.Clone()
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", fmt.Sprintf("%s://%s",parse.Scheme,parse.Host))
	//request.Form = r.Form
	log.Println(r.Form)
	//request.MultipartForm = r.MultipartForm
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
	readAll, err := io.ReadAll(resp.Body)
	if err != nil {
		write503(w, err)
		return
	}
	//log.Println(string(readAll))
	decrypt, err := Decrypt(string(readAll), GetAesKey())
	if err != nil {
		write503(w, err)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(decrypt)))
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, strings.NewReader(decrypt))
	if err != nil {
		log.Println(err)
	}
}

func GetAesKey() []byte {
	return []byte(os.Getenv("AesKey"))
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

func Encrypt(text []byte, key []byte) (string, error) {
	return string(text),nil
	// if len(key) > 16 {
	// 	key = key[:16]
	// }
	// if len(key) < 16 {
	// 	for len(key) < 16 {
	// 		key = append(key, 'x')
	// 	}
	// }
	// //生成cipher.Block 数据块
	// block, err := aes.NewCipher(key)
	// if err != nil {
	// 	log.Println("错误 -" + err.Error())
	// 	return "", err
	// }
	// blockSize := block.BlockSize()
	// //填充内容，如果不足16位字符
	// originData := pad(text, blockSize)
	// //加密，输出到[]byte数组
	// crypted := make([]byte, len(originData)+blockSize)
	// //填充随机数
	// iv := crypted[:blockSize]
	// _, err = io.ReadFull(rand.Reader, iv)
	// if err != nil {
	// 	return "", err
	// }
	// //加密方式
	// blockMode := cipher.NewCBCEncrypter(block, iv)
	// blockMode.CryptBlocks(crypted[blockSize:], originData)
	// return base64.StdEncoding.EncodeToString(crypted), nil
}

func pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	//log.Println(padding)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func Decrypt(text string, key []byte) (string, error) {
	return text,nil
	// if len(text) == 0 {
	// 	return text, nil
	// }
	// if len(key) > 16 {
	// 	key = key[:16]
	// }
	// if len(key) < 16 {
	// 	for len(key) < 16 {
	// 		key = append(key, 'x')
	// 	}
	// }
	// decode_data, err := base64.StdEncoding.DecodeString(text)
	// if err != nil {
	// 	return "", err
	// }
	// //生成密码数据块cipher.Block
	// block, _ := aes.NewCipher(key)
	// log.Println(block.BlockSize())
	// //解密模式
	// blockMode := cipher.NewCBCDecrypter(block, decode_data[:block.BlockSize()])
	// //输出到[]byte数组
	// origin_data := make([]byte, len(decode_data)-block.BlockSize())
	// blockMode.CryptBlocks(origin_data, decode_data[block.BlockSize():])
	// log.Println(origin_data)
	// log.Println(len(origin_data))
	// //去除填充,并返回
	// return string(unpad(origin_data)), nil
}

func unpad(ciphertext []byte) []byte {
	length := len(ciphertext)
	//去掉最后一次的padding
	unpadding := int(ciphertext[length-1])
	//log.Println(unpadding)
	return ciphertext[:(length - unpadding)]
}

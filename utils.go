package main

import (
	//	"archive/tar"
	//	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jaytaylor/html2text"
	//	gzip "github.com/klauspost/pgzip"
	"github.com/melbahja/got"
	"github.com/microcosm-cc/bluemonday"
	"h12.io/socks"
	"html"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	nu "net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13",
	"Mozilla/5.0 (Windows; U; Windows NT 6.0; de) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; pt-PT; rv:1.9.2.7) Gecko/20100713 Firefox/3.6.7 (.NET CLR 3.5.30729)",
	"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.6) Gecko/20100628 Ubuntu/10.04 (lucid) Firefox/3.6.6 GTB7.1",
	"Mozilla/5.0 (X11; Mageia; Linux x86_64; rv:10.0.9) Gecko/20100101 Firefox/10.0.9",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0a2) Gecko/20111101 Firefox/9.0a2",
	"Mozilla/5.0 (Windows NT 6.2; rv:9.0.1) Gecko/20100101 Firefox/9.0.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
}
var localIP string

func Init() {
	rand.Seed(time.Now().Unix())
}
func RandItem(arr *[]string) string {

	return (*arr)[rand.Intn(len(*arr))]
}

func Append_file(fn string, str string) {

	// fopen files r and w
	file, err := os.OpenFile(fn, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	defer file.Close()

	if _, err = file.WriteString(fmt.Sprintf("%s\n", str)); err != nil {
		fmt.Println(err)

		panic(err)
	}

}
func Append_file2(fn string, str string) {

	// fopen files r and w
	file, err := os.OpenFile(fn, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	defer file.Close()

	if _, err = file.WriteString(fmt.Sprintf("%s", str)); err != nil {
		fmt.Println(err)

		panic(err)
	}

}

func DownloadFile(url string, filepath string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
func WalkMatch(root, pattern string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}
func RemoveContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func killSpacesAndDots(s string) string {

	return strings.TrimSpace(strings.Replace(strings.Replace(s, ".", "", -1), " ", "", -1))
}

func CleanText(txt string) string {
	p := bluemonday.UGCPolicy()
	return html.UnescapeString(p.Sanitize(strings.Replace(strings.Replace(strings.Replace(strings.Replace(strings.Replace(strings.Replace(txt, "&nbsp;", "", -1), "&amp;", "", -1), "\"", "", -1), "'", "", -1), ";", "", -1), "\t", " ", -1)))

}
func WriteTxt(filename string, content *string) (err error) {
	err = ioutil.WriteFile(filename, []byte(*content), 0644)
	if err != nil {
		return err
	}
	return nil
}
func Unique(slice []string) []string {
	// create a map with all the values as key
	uniqMap := make(map[string]struct{})
	for _, v := range slice {
		uniqMap[v] = struct{}{}
	}

	// turn the map keys into a slice
	uniqSlice := make([]string, 0, len(uniqMap))
	for v := range uniqMap {
		uniqSlice = append(uniqSlice, v)
	}
	return uniqSlice
}
func prepDir(out_dir string, clean bool) {
	_ = os.Mkdir(out_dir, os.ModePerm)
	if clean {
		RemoveContents(out_dir)
	}
}

func GetUA() {
	lst, _ := LoadPList("./ua.txt")
	UserAgents = Unique(append(UserAgents, (*lst)...))
}
func LoadPList(rfile string) (px *[]string, err error) {
	px = new([]string)
	_, err = os.Stat(rfile)
	if os.IsNotExist(err) {
		return px, errors.New(rfile + " does not exist")
	}

	file, err := ioutil.ReadFile(rfile)
	if err != nil {
		return px, err
	}

	for _, proxy := range strings.Split(string(file), "\n") {
		if len(strings.TrimSuffix(strings.TrimSuffix(proxy, "\r"), "\n")) > 0 {

			*px = append(*px, strings.TrimSuffix(proxy, "\r"))
		}
	}

	if len(*px) < 1 {
		return px, errors.New(rfile + " does not contain any list")
	}

	return px, err
}
func RandomOption(options []string) string {
	rand.Seed(time.Now().Unix())
	randNum := rand.Int() % len(options)
	return options[randNum]
}

func LoadList(rfile string) (px []string, err error) {

	_, err = os.Stat(rfile)
	if os.IsNotExist(err) {
		return px, errors.New(rfile + " does not exist")
	}

	file, err := ioutil.ReadFile(rfile)
	if err != nil {
		return px, err
	}

	text := string(file)

	for _, proxy := range strings.Split(text, "\n") {
		if len(strings.TrimSuffix(strings.TrimSuffix(proxy, "\r"), "\n")) > 0 {
			px = append(px, strings.TrimSuffix(proxy, "\r"))
		}
	}

	if len(px) < 1 {
		return px, errors.New(rfile + " does not contain any list")
	}

	return px, err
}

func ExtractProxyIPs(html *string) []string {
	out := make([]string, 0)
	ip := regexp.MustCompile(`(\d*\.\d*\.\d*\.\d*\:\d*)\b`)
	ip3 := regexp.MustCompile(`(\d*\.\d*\.\d*\.\d*\\\\d*)\b`)
	ip4 := regexp.MustCompile(`(\d*\.\d*\.\d*\.\d*\\/\d*)\b`)
	ip2 := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s+|\s*:\s*|\s*\\\s*|\s*\/\s*|\S.*)(\d{2,5})`)
	text, err := html2text.FromString(*html, html2text.Options{})
	if err == nil {
		ips := ip.FindAllString(text, -1)
		out = append(out, ips...)
		ips = ip2.FindAllString(text, -1)

		for i := 0; i < len(ips); i++ {
			ips[i] = strings.Replace(strings.Replace(strings.Replace(strings.Replace(ips[i], "\t", ":", -1), " ", ":", -1), "\\", ":", -1), "/", ":", -1)

		}
		out = append(out, ips...)
	}

	ips := ip.FindAllString(*html, -1)
	out = append(out, ips...)
	ips = ip3.FindAllString(*html, -1)
	out = append(out, ips...)
	ips = ip4.FindAllString(*html, -1)
	//log.Printf("%v",ips)
	out = append(out, ips...)

	return Unique(out)
}

func GetSelfIP() string {
	var ProxyCheckURL string = "https://api.ipify.org?format=text"
	timeout := time.Duration(10 * time.Second)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(ProxyCheckURL)
	if err == nil {

		if resp.StatusCode == http.StatusOK {

			sdata, err := ioutil.ReadAll(resp.Body)
			//	  size, err := io.Copy(file, resp.Body)
			if err == nil {

				resp.Body.Close()
				localIP = strings.Trim(string(sdata), " ")
				log.Printf("Launcher Self  ip=%s", localIP)
			}
		}
	}

	return localIP
}

func MultyThreadsDownloadRaw(url string, store string, proxy *[]string) {

	if proxy == nil || len(*proxy) == 0 {
		g := got.New()

		err := g.Download(url, store)
		if err != nil {
			log.Printf("%v", err)
		}
	} else {
	start:
		px := RandomOption(*proxy)
		g := got.New()
		log.Printf("Download  with proxy:%s", px)
		proxy_url, err := nu.Parse(px)
		if err != nil {
			log.Printf("url parse err %v", err)
		}
		if strings.Contains(px, "http") {

			g.Client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy_url), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: (&net.Dialer{
				Timeout:   160 * time.Second,
				KeepAlive: 160 * time.Second,
				DualStack: true,
			}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 3 * time.Second}, Timeout: time.Duration(100) * time.Second}
			err = g.Download(url, store)
			if err != nil {
				log.Printf("%v", err)
				goto start
			}
		}

		if strings.Contains(px, "socks") {

			dialSocksProxy := socks.Dial(px)
			tr := &http.Transport{Dial: dialSocksProxy, TLSHandshakeTimeout: 5 * time.Second, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

			g.Client = &http.Client{Transport: tr, Timeout: time.Duration(100) * time.Second}
			err = g.Download(url, store)
			if err != nil {
				log.Printf("%v", err)
				goto start
			}
		}

	}
}

func DownloadFileWProxy(url string, filepath string, proxy *[]string) error {
	// Get the data
	px := RandomOption(*proxy)
	proxy_url, err := nu.Parse(px)
	if err != nil {
		log.Printf("url parse err %v", err)
	}

	client := &http.Client{Timeout: time.Duration(1000) * time.Second}
	if strings.Contains(px, "http") {

		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxy_url), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: (&net.Dialer{
			Timeout:   160 * time.Second,
			KeepAlive: 160 * time.Second,
			DualStack: true,
		}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 30 * time.Second}

	}

	if strings.Contains(px, "socks") {

		dialSocksProxy := socks.Dial(px)
		tr := &http.Transport{Dial: dialSocksProxy, TLSHandshakeTimeout: 5 * time.Second, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: (&net.Dialer{
			Timeout:   160 * time.Second,
			KeepAlive: 160 * time.Second,
			DualStack: true,
		}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       190 * time.Second,
			ExpectContinueTimeout: 30 * time.Second}

		client.Transport = tr
	}

	resp, err := client.Get(url)

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

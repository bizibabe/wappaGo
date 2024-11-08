package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	URL "net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/EasyRecon/wappaGo/analyze"
	"github.com/EasyRecon/wappaGo/lib"
	"github.com/EasyRecon/wappaGo/report"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/EasyRecon/wappaGo/utils"
	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/goccy/go-json"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	pdhttputil "github.com/projectdiscovery/httputil"
	"github.com/remeh/sizedwaitgroup"
)

type Cmd struct {
	ChromeCtx    context.Context
	Dialer       *fastdialer.Dialer
	ResultGlobal map[string]interface{}
	Cdn          *cdncheck.Client
	Options      structure.Options
	PortOpenByIP []structure.PortOpenByIp
	HttpClient   *http.Client
	ResultArray  []structure.Data
	Input        []string
}

func (c *Cmd) Start(results chan structure.Data) {
	c.Dialer = c.InitDialer()
	defer c.Dialer.Close()

	optionsChromeCtx := []chromedp.ExecAllocatorOption{}
	optionsChromeCtx = append(optionsChromeCtx, chromedp.DefaultExecAllocatorOptions[:]...)
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("headless", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("disable-popup-blocking", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.DisableGPU)
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("disable-webgl", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("ignore-certificate-errors", true)) // RIP shittyproxy.go
	optionsChromeCtx = append(optionsChromeCtx, chromedp.WindowSize(1400, 900))
	if *c.Options.Proxy != "" {
		optionsChromeCtx = append(optionsChromeCtx, chromedp.ProxyServer(*c.Options.Proxy))
	}

	//ctxAlloc, cancel := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false), chromedp.Flag("disable-gpu", true))...)
	ctxAlloc, cancel1 := chromedp.NewExecAllocator(context.Background(), optionsChromeCtx...)
	defer cancel1()

	ctxAlloc1, cancel := chromedp.NewContext(ctxAlloc)
	c.ChromeCtx = ctxAlloc1
	defer cancel()

	if err := chromedp.Run(c.ChromeCtx); err != nil {
		panic(err)
	}

	c.Cdn = cdncheck.New()
	var url string
	var ip string
	swg := sizedwaitgroup.New(*c.Options.Threads)
	url = ""
	ip = ""
	for _, line := range c.Input {
		if *c.Options.AmassInput {
			var result map[string]interface{}
			json.Unmarshal([]byte(line), &result)
			url = result["name"].(string)
			ip = result["addresses"].([]interface{})[0].(map[string]interface{})["ip"].(string)
		} else {
			url = line
		}
		swg.Add()
		go func(url string, ip string) {
			defer swg.Done()
			c.startPortScan(url, ip, results)
		}(url, ip)
	}
	swg.Wait()
	close(results)
}

func (c *Cmd) startPortScan(url string, ip string, results chan structure.Data) {
	portList := strings.Split(*c.Options.Ports, ",")
	swg1 := sizedwaitgroup.New(50)
	swg := sizedwaitgroup.New(*c.Options.ChromeThreads)
	var CdnName string
	portTemp := portList
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext:       c.Dialer.Dial,
		DisableKeepAlives: true,
	}
	if *c.Options.Proxy != "" {
		proxyURL, parseErr := URL.Parse(*c.Options.Proxy)
		if parseErr == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
			transport.TLSClientConfig.MaxVersion = tls.VersionTLS12
		}
	}
	c.HttpClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	if !*c.Options.FollowRedirect {
		c.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			//data.Infos.Location = fmt.Sprintf("%s", req.URL)
			return http.ErrUseLastResponse
		}
	}

	if !*c.Options.AmassInput {
		c.HttpClient.Get("http://" + url)
		ip = c.Dialer.GetDialedIP(url)
	}
	isCDN, cdnName, _, err := c.Cdn.Check(net.ParseIP(ip))
	//fmt.Println(isCDN, ip)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println(isCDN)
	// Vérifier si l'option -ports est spécifiée
	if *c.Options.Ports != "" {
		portTemp = strings.Split(*c.Options.Ports, ",")
	} else if isCDN {
		portTemp = []string{"80", "443"}
		CdnName = cdnName
	}

	var portOpen []string
	alreadyScanned := lib.CheckIpAlreadyScan(ip, c.PortOpenByIP)
	if alreadyScanned.IP != "" {
		portOpen = alreadyScanned.Open_port
	} else {
		for _, portEnum := range portTemp {
			swg1.Add()
			go func(portEnum string, url string) {
				defer swg1.Done()
				openPort := c.scanPort("tcp", url, portEnum, *c.Options.Porttimeout)
				if openPort {
					portOpen = append(portOpen, portEnum)
				}
			}(portEnum, url)
		}
		swg1.Wait()
		var tempScanned structure.PortOpenByIp
		tempScanned.IP = ip
		tempScanned.Open_port = portOpen
		c.PortOpenByIP = append(c.PortOpenByIP, tempScanned)
	}
	url = strings.TrimSpace(url)
	for _, port := range portOpen {
		swg.Add()
		go func(port string, url string, portOpen []string, CdnName string, c *Cmd) {
			defer swg.Done()
			data := structure.Data{}
			data.Infos.CDN = CdnName
			data.Infos.Data = url
			data.Infos.Ports = portOpen
			data.Infos.IP = ip
			c.getWrapper(url, port, data, results)
		}(port, url, portOpen, CdnName, c)
	}
	swg.Wait()
}

func (c *Cmd) getWrapper(urlData string, port string, data structure.Data, results chan structure.Data) {
	errorContinue := true
	var urlDataPort string
	var resp *structure.Response
	if port != "80" && port != "443" {
		urlDataPort = urlData + ":" + port
	} else {
		urlDataPort = urlData
	}

	// Construire l'URL initiale complète
	initialURL := "http://" + urlDataPort
	if port == "443" {
		initialURL = "https://" + urlDataPort
	}

	initialParsedURL, err := url.Parse(initialURL)
	if err != nil {
		msg := fmt.Sprintf("Error parsing initial URL %s: %v", initialURL, err)
		jsonResponse := utils.GenerateErrorMessage("Target changed", msg)

		// Print the JSON response
		fmt.Println(string(jsonResponse))
		return
	}
	initialDomain := initialParsedURL.Hostname()
	initialPort := initialParsedURL.Port()
	if initialPort == "" {
		// Si le port n'est pas spécifié, utiliser le port par défaut en fonction du schéma
		if initialParsedURL.Scheme == "https" {
			initialPort = "443"
		} else {
			initialPort = "80"
		}
	}

	if *c.Options.FollowRedirect {
		// Utiliser chromedp pour suivre les redirections JavaScript
		ctx, cancel := chromedp.NewContext(c.ChromeCtx)
		defer cancel()

		var finalURL string
		var statusCode int64
		var redirectChain []string

		// Écouter les événements réseau pour capturer la chaîne de redirection et le code de statut
		chromedp.ListenTarget(ctx, func(ev interface{}) {
			switch ev := ev.(type) {
			case *network.EventRequestWillBeSent:
				if ev.Type == network.ResourceTypeDocument {
					redirectChain = append(redirectChain, ev.Request.URL)
				}
			case *network.EventResponseReceived:
				if ev.Type == network.ResourceTypeDocument {
					statusCode = int64(ev.Response.Status)
				}
			}
		})

		// Exécuter les actions chromedp pour naviguer et capturer l'URL finale
		err = chromedp.Run(ctx,
			network.Enable(),
			chromedp.Navigate(initialURL),
			chromedp.WaitReady("body"),
			chromedp.Evaluate(`window.location.href`, &finalURL),
		)
		if err != nil {
			msg := fmt.Sprintf("The domain has changed from %s: %v", initialURL, err)
			jsonResponse := utils.GenerateErrorMessage("Target changed", msg)

			// Print the JSON response
			fmt.Println(string(jsonResponse))
			return
		}

		// Analyser l'URL finale pour obtenir le domaine et le port
		finalParsedURL, err := url.Parse(finalURL)
		if err != nil {
			msg := fmt.Sprintf("The domain has changed from %s: %v", finalURL, err)
			jsonResponse := utils.GenerateErrorMessage("Target changed", msg)

			// Print the JSON response
			fmt.Println(string(jsonResponse))
			return
		}
		finalDomain := finalParsedURL.Hostname()
		finalPort := finalParsedURL.Port()
		if finalPort == "" {
			// Si le port n'est pas spécifié, utiliser le port par défaut en fonction du schéma
			if finalParsedURL.Scheme == "https" {
				finalPort = "443"
			} else {
				finalPort = "80"
			}
		}

		// Vérifier si le domaine ou le port a changé
		if initialDomain != finalDomain || initialPort != finalPort {
			msg := fmt.Sprintf("The domain or port has changed from %s:%s to %s:%s", initialDomain, initialPort, finalDomain, finalPort)
			jsonResponse := utils.GenerateErrorMessage("Target changed", msg)

			// Print the JSON response
			fmt.Println(string(jsonResponse))
			// fmt.Println("Chaîne de redirection :")
			// for _, u := range redirectChain {
			// 	fmt.Println("->", u)
			// }
			return
		}

		// Continuer avec le reste du traitement
		data.Infos.Status_code = int(statusCode)
		data.Infos.Scheme = finalParsedURL.Scheme
		data.Url = finalURL

		// Appeler launchChrome avec l'URL finale
		c.launchChrome(structure.Response{}, data, finalURL, port, results)
	} else {
		// Utiliser le client HTTP standard sans suivre les redirections
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		if *c.Options.Proxy != "" {
			proxyURL, parseErr := url.Parse(*c.Options.Proxy)
			if parseErr == nil {
				http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
				http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
			}
		}
		client := c.getClientCtx()

		// S'assurer que le client ne suit pas les redirections
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var TempResp structure.Response
		var errSSL error
		if port != "80" {
			request, _ := http.NewRequest("GET", "https://"+urlDataPort, nil)
			resp, errSSL = Do(request, client, false)
		}
		if errSSL != nil || port == "80" {
			if port == "443" {
				errorContinue = false
			} else {
				request, _ := http.NewRequest("GET", "http://"+urlDataPort, nil)
				resp, errPlain := Do(request, client, false)
				if errPlain != nil || resp == nil {
					errorContinue = false
				} else {
					data, TempResp, _ = c.DefineBasicMetric(data, resp)
					if data.Infos.Scheme == "" {
						data.Infos.Scheme = "http"
					}
					urlData = "http://" + urlDataPort
					data.Url = urlData
				}
			}
		} else {
			data, TempResp, _ = c.DefineBasicMetric(data, resp)
			if data.Infos.Scheme == "" {
				data.Infos.Scheme = "https"
			}
			urlData = "https://" + urlDataPort
			data.Url = urlData
		}

		if errorContinue {
			// Comparer les domaines et les ports
			var finalDomain string
			var finalPort string
			if resp != nil && resp.URL != nil {
				finalDomain = resp.URL.Hostname()
				finalPort = resp.URL.Port()
				if finalPort == "" {
					// Si le port n'est pas spécifié, utiliser le port par défaut en fonction du schéma
					if resp.URL.Scheme == "https" {
						finalPort = "443"
					} else {
						finalPort = "80"
					}
				}
			} else {
				finalDomain = initialDomain
				finalPort = initialPort
			}

			if initialDomain != finalDomain || initialPort != finalPort {

				msg := fmt.Sprintf("The domain or port has changed from %s:%s to %s:%s", initialDomain, initialPort, finalDomain, finalPort)
				jsonResponse := utils.GenerateErrorMessage("Target changed", msg)

				// Print the JSON response
				fmt.Println(string(jsonResponse))
				return
			}

			c.launchChrome(TempResp, data, urlData, port, results)
		}
	}
}

func (c *Cmd) launchChrome(TempResp structure.Response, data structure.Data, urlData string, port string, results chan structure.Data) {
	var err error
	if data.Infos.Location != "" {
		urlData = data.Infos.Location
	}
	dnsData, err := c.Dialer.GetDNSData(data.Infos.Data)
	if dnsData != nil && err == nil {
		data.Infos.Cname = dnsData.CNAME
	}
	analyseStruct := analyze.Analyze{}
	ctxAlloc1, _ := context.WithTimeout(c.ChromeCtx, 60*time.Second)
	cloneCTX, cancel := chromedp.NewContext(ctxAlloc1)
	chromedp.ListenTarget(cloneCTX, func(ev interface{}) {
		if responseEvent, ok := ev.(*network.EventResponseReceived); ok {
			// Store headers in TempResp.Headers
			if TempResp.Headers == nil {
				TempResp.Headers = make(map[string][]string)
			}
			for key, value := range responseEvent.Response.Headers {
				// Ensure the value is converted to []string
				switch v := value.(type) {
				case string:
					TempResp.Headers[key] = []string{v}
				case []string:
					TempResp.Headers[key] = v
				}
			}

			// Process document types
			switch typeDoc := responseEvent.Type; typeDoc {
			case "XHR":
				analyseStruct.XHRUrl = append(analyseStruct.XHRUrl, responseEvent.Response.URL)
			case "Stylesheet":
				// Stylesheet processing (currently commented)
			case "Script":
				// Script processing (currently commented)
			}
		}
		// Handling JavaScript dialog if it opens
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			go func() {
				if err := chromedp.Run(cloneCTX,
					page.HandleJavaScriptDialog(true),
				); err != nil {
					b, err := json.Marshal(data)
					if err != nil {
						fmt.Println("Error:", err)
					}
					fmt.Println(string(b))
					return
				}
			}()
		}
	})

	defer cancel()

	// Run task list
	var buf []byte
	err = chromedp.Run(cloneCTX,
		chromedp.Navigate(urlData),
		chromedp.Title(&data.Infos.Title),
		chromedp.CaptureScreenshot(&buf),
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookiesList, _ := network.GetCookies().Do(ctx)
			if strings.HasPrefix(urlData, "https://") {
				sslcert, _ := network.GetCertificate(urlData).Do(ctx)
				if len(sslcert) > 0 {
					sDec, _ := base64.StdEncoding.DecodeString(sslcert[0])
					cert, _ := x509.ParseCertificate(sDec)
					analyseStruct.CertVhost = cert.DNSNames
					analyseStruct.CertIssuer = cert.Issuer.CommonName
				}
			}
			node, err_node := dom.GetDocument().Do(ctx)
			if err_node != nil {
				return err_node
			}
			body, err := dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			if err == nil {
				reader := strings.NewReader(body)
				doc, err := goquery.NewDocumentFromReader(reader)
				if err != nil {
					log.Fatal(err)
				}
				var srcList []string
				doc.Find("script").Each(func(i int, s *goquery.Selection) {
					srcLink, exist := s.Attr("src")
					if exist {
						srcList = append(srcList, srcLink)
					}
				})
				analyseStruct.SrcList = srcList
				analyseStruct.Body = body
			}

			analyseStruct.ResultGlobal = c.ResultGlobal
			analyseStruct.Resp = TempResp
			analyseStruct.Ctx = ctx
			analyseStruct.Hote = data.Infos
			analyseStruct.CookiesList = cookiesList
			analyseStruct.Node = node
			analyseStruct.Technos = []structure.Technologie{}
			analyseStruct.DnsData = dnsData
			data.Infos.Technologies = analyseStruct.Run()
			data.Infos.CertVhost = analyseStruct.CertVhost
			return nil
		}),
	)

	data.Infos.Technologies = technologies.DedupTechno(data.Infos.Technologies)
	if *c.Options.Screenshot != "" && len(buf) > 0 {
		imgTitle := strings.Replace(urlData, ":", "_", -1)
		imgTitle = strings.Replace(imgTitle, "/", "", -1)
		imgTitle = strings.Replace(imgTitle, ".", "_", -1)
		file, _ := os.OpenFile(
			*c.Options.Screenshot+"/"+imgTitle+".png",
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		file.Write(buf)
		file.Close()
		data.Infos.Screenshot = imgTitle + ".png"
	}
	if *c.Options.Report {
		c.ResultArray = append(c.ResultArray, data)
	} else {
		results <- data
	}
	if *c.Options.Report {
		report.Report_main(c.ResultArray, *c.Options.Screenshot)
	}
}

func (c *Cmd) scanPort(protocol, hostname string, port string, portTimeout int) bool {
	address := hostname + ":" + port
	conn, err := net.DialTimeout(protocol, address, time.Duration(portTimeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// Do http request
func Do(req *http.Request, parentClient *http.Client, followRedirect bool) (*structure.Response, error) {
	var gzipRetry bool
	var redirectChain []*url.URL
	finalURL := req.URL

	// Clone le transport du client parent
	transport, ok := parentClient.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("unsupported transport type")
	}

	newTransport := transport.Clone()

	// Créer un nouveau client avec une fonction CheckRedirect personnalisée
	client := &http.Client{
		Transport: newTransport,
		Timeout:   parentClient.Timeout,
		Jar:       parentClient.Jar,
	}

	if followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			redirectChain = append(redirectChain, req.URL)
			finalURL = req.URL
			return nil // Continue à suivre les redirections
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Ne pas suivre les redirections
		}
	}

get_response:
	httpresp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	var resp structure.Response

	// Définit resp.URL sur l'URL finale après toutes les redirections
	resp.URL = finalURL
	resp.RedirectChain = redirectChain // Stocke la chaîne de redirection

	// httputil.DumpResponse does not handle websockets
	headers, rawResp, err := pdhttputil.DumpResponseHeadersAndRaw(httpresp)
	if err != nil {
		// Edge case - some servers respond with gzip encoding header but uncompressed body, in this case the standard library configures the reader as gzip, triggering an error when read.
		// The bytes slice is not accessible because of abstraction, therefore we need to perform the request again tampering the Accept-Encoding header
		if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
			gzipRetry = true
			req.Header.Set("Accept-Encoding", "identity")
			goto get_response
		}

		return nil, err
	}
	resp.Raw = string(rawResp)
	//fmt.Println(resp.RawHeaders)
	resp.RawHeaders = string(headers)

	var respbody []byte
	// websockets don't have a readable body
	if httpresp.StatusCode != http.StatusSwitchingProtocols {
		var err error
		respbody, err = ioutil.ReadAll(io.LimitReader(httpresp.Body, 4096))
		if err != nil {
			return nil, err
		}
	}

	closeErr := httpresp.Body.Close()
	if closeErr != nil {
		return nil, closeErr
	}

	respbodystr := string(respbody)

	// if content length is not defined
	if resp.ContentLength <= 0 {
		// check if it's in the header and convert to int
		if contentLength, ok := resp.Headers["Content-Length"]; ok {
			contentLengthInt, _ := strconv.Atoi(strings.Join(contentLength, ""))
			resp.ContentLength = contentLengthInt
		}

		// if we have a body, then use the number of bytes in the body if the length is still zero
		if resp.ContentLength <= 0 && len(respbodystr) > 0 {
			resp.ContentLength = utf8.RuneCountInString(respbodystr)
		}
	}

	resp.Data = respbody

	// fill metrics
	resp.StatusCode = httpresp.StatusCode
	// number of words
	resp.Words = len(strings.Split(respbodystr, " "))
	// number of lines
	resp.Lines = len(strings.Split(respbodystr, "\n"))

	return &resp, nil
}

func (c *Cmd) InitDialer() *fastdialer.Dialer {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true

	if len(*c.Options.Resolvers) == 0 {
		*c.Options.Resolvers = "8.8.8.8,1.1.1.1,64.6.64.6,74.82.42.42,1.0.0.1,8.8.4.4,64.6.65.6,77.88.8.8"
	}
	fastdialerOpts.BaseResolvers = strings.Split(*c.Options.Resolvers, ",")

	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		fmt.Errorf("could not create resolver cache: %s", err)
	}
	return dialer
}

func (c *Cmd) getClientCtx() *http.Client {
	if c.HttpClient == nil {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext:       c.Dialer.Dial,
			DisableKeepAlives: true,
		}
		if *c.Options.Proxy != "" {
			proxyURL, parseErr := URL.Parse(*c.Options.Proxy)
			if parseErr == nil {
				transport.Proxy = http.ProxyURL(proxyURL)
				transport.TLSClientConfig.MinVersion = tls.VersionTLS12
				transport.TLSClientConfig.MaxVersion = tls.VersionTLS12
			}
		}
		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
		// Ne pas définir CheckRedirect ici, il sera géré dans la fonction Do
		return client
	} else {
		return c.HttpClient
	}
}

func (c *Cmd) DefineBasicMetric(data structure.Data, resp *structure.Response) (structure.Data, structure.Response, error) {

	if (resp.StatusCode == 301 || resp.StatusCode == 302) && len(resp.Headers["Location"]) > 0 {
		data.Infos.Location = resp.Headers["Location"][0]
	}
	if len(resp.Headers["Content-Type"]) > 0 {
		data.Infos.Content_type = strings.Split(resp.Headers["Content-Type"][0], ";")[0]
	}
	data.Infos.Response_time = resp.Duration
	data.Infos.Content_length = resp.ContentLength
	data.Infos.Status_code = resp.StatusCode
	return data, *resp, nil
}

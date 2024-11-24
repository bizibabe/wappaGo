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
	"github.com/EasyRecon/wappaGo/report"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/EasyRecon/wappaGo/utils"
	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
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
	defer func() {
		c.Dialer.Close()
	}()

	optionsChromeCtx := []chromedp.ExecAllocatorOption{
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.Flag("ignore-certificate-errors", true),
	}
	if *c.Options.Proxy != "" {
		optionsChromeCtx = append(optionsChromeCtx, chromedp.ProxyServer(*c.Options.Proxy))
	}

	tempDir, err := os.MkdirTemp("", "chromedp-profile-*")
	if err != nil {
		utils.SendError(results, "", fmt.Sprintf("Failed to create temp dir: %v", err))
		return
	}
	defer os.RemoveAll(tempDir) // Nettoyage du répertoire temporaire à la fin

	optionsChromeCtx = append(optionsChromeCtx, chromedp.UserDataDir(tempDir))

	ctxAlloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), optionsChromeCtx...)
	defer cancelAlloc()

	ctx, cancelCtx := chromedp.NewContext(ctxAlloc)
	c.ChromeCtx = ctx
	defer cancelCtx()

	if err := chromedp.Run(c.ChromeCtx); err != nil {
		utils.SendError(results, "", fmt.Sprintf("Error initializing Chrome: %v", err))
		return
	}

	c.Cdn = cdncheck.New()

	swg := sizedwaitgroup.New(*c.Options.Threads)
	for _, line := range c.Input {
		target := line
		parsedURL, err := url.Parse(line)
		var targetIP string
		if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
			targetIP = c.Dialer.GetDialedIP(parsedURL.Host)
		} else {
			targetIP = c.Dialer.GetDialedIP(line)
		}

		swg.Add()
		go func(url, ip string) {
			defer swg.Done()
			defer func() {
				if r := recover(); r != nil {
					utils.SendError(results, "", fmt.Sprintf("Recovered from panic in Goroutine: %v", r))
					return
				}
			}()
			c.startPortScan(url, ip, results)
		}(target, targetIP)
	}
	swg.Wait()
	close(results)
}

func (c *Cmd) startPortScan(target string, inputIP string, results chan structure.Data) {
    var inputURL string
    var isDomain bool
    portList := strings.Split(*c.Options.Ports, ",")
    swg := sizedwaitgroup.New(*c.Options.ChromeThreads) // Gestion des goroutines pour les threads Chrome
    var CdnName string

    // Configuration du transport HTTP
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
        DialContext:       c.Dialer.Dial,
        DisableKeepAlives: true,
    }
    if *c.Options.Proxy != "" {
        proxyURL, parseErr := url.Parse(*c.Options.Proxy)
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

    if !strings.HasPrefix(target, "http") {
        inputURL = "http://" + target
        isDomain = true
    } else {
        inputURL = target
        isDomain = false
    }
    parsedURL, err := url.Parse(inputURL)
    if err != nil {
        utils.SendError(results, "", fmt.Sprintf("Invalid URL: %s", target))
        return
    }
    hostname := parsedURL.Hostname()

    // Déterminer les ports en fonction du schéma
    var portTemp []string
    if !isDomain && parsedURL.Scheme != "" && parsedURL.Host != "" {
        if parsedURL.Scheme == "https" && parsedURL.Port() == "" {
            portTemp = []string{"443"}
        } else if parsedURL.Scheme == "http" && parsedURL.Port() == "" {
            portTemp = []string{"80"}
        } else {
            portTemp = []string{parsedURL.Port()}
        }
    } else {
        portTemp = portList
    }

    // Vérification CDN
    isCDN, cdnName, _, err := c.Cdn.Check(net.ParseIP(inputIP))
    if err != nil {
        utils.SendError(results, target, fmt.Sprintf("Error checking CDN: %s", err))
        return
    }
    if isCDN {
        CdnName = cdnName
    }

    // Analyse des ports
    for _, port := range portTemp {
        swg.Add()
        go func(port string) {
            defer swg.Done()
            openPort := c.reliablePortScan("tcp", hostname, port, *c.Options.Porttimeout)
            data := structure.Data{
                Infos: structure.Host{
                    Port: port,
                    Data: target,
                    IP:   inputIP,
                    CDN:  CdnName,
                },
            }

            if !openPort {
                utils.SendError(results, target, fmt.Sprintf("Port %s on %s is closed", port, hostname))
                return
            }

            // Traiter le port ouvert
            c.getWrapper(inputURL, port, data, results)
        }(port)
    }
    swg.Wait()
}


func (c *Cmd) reliablePortScan(protocol, hostname, port string, portTimeout int) bool {
	address := hostname + ":" + port
	retryCount := 3
	for i := 0; i < retryCount; i++ {
		conn, err := net.DialTimeout(protocol, address, time.Duration(portTimeout)*time.Millisecond)
		if err == nil {
			conn.Close()
			return true // Port is open
		}
		// Optionally add a small delay between retries if needed
		time.Sleep(100 * time.Millisecond)
	}
	return false // Port is considered closed after retries
}

func (c *Cmd) getWrapper(inputURL string, port string, data structure.Data, results chan structure.Data) {

	var urlDataPort string
	var resp *structure.Response
	errorContinue := true

	parsedURL, err := url.Parse(inputURL)

	if err != nil {
		utils.SendError(results, inputURL, fmt.Sprintf("Error parsing input URL %s: %v", inputURL, err))
		return
	}

	if port != "80" && port != "443" && parsedURL.Port() == "" {
		urlDataPort = parsedURL.Scheme + "://" + parsedURL.Hostname() + ":" + port
	} else if port == "443" {
		urlDataPort = "https://" + parsedURL.Hostname()
	} else if port == "80" {
		urlDataPort = "http://" + parsedURL.Hostname()
	} else {
		urlDataPort = inputURL
	}

	// Construct initial URL for request
	initialURL := urlDataPort
	initialParsedURL, err := url.Parse(initialURL)
	if err != nil {
		utils.SendError(results, inputURL, fmt.Sprintf("Error parsing initial URL %s: %v", initialURL, err))
		return
	}

	initialDomain := initialParsedURL.Hostname()
	initialPort := initialParsedURL.Port()
	if initialPort == "" {
		// Default to the appropriate port based on the scheme
		if initialParsedURL.Scheme == "https" {
			initialPort = "443"
		} else {
			initialPort = "80"
		}
	}

	// Follow redirects if option is enabled
	if *c.Options.FollowRedirect {
		timeoutCtx, cancel := context.WithTimeout(c.ChromeCtx, 60*time.Second)
		defer cancel()

		ctx, cancelCtx := chromedp.NewContext(timeoutCtx)
		defer cancelCtx()

		var finalURL string
		var statusCode int64
		var redirectChain []string

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

		err = chromedp.Run(ctx,
			network.Enable(),
			network.SetCacheDisabled(true),
			chromedp.Navigate(initialURL),
			chromedp.WaitReady("body"),
			chromedp.Evaluate(`window.location.href`, &finalURL),
		)
		if err != nil {
			utils.SendError(results, inputURL, fmt.Sprintf("Webdriver error : %v", err))
			return
		}

		finalParsedURL, err := url.Parse(finalURL)
		if err != nil {
			utils.SendError(results, inputURL, fmt.Sprintf("Error parsing final URL %s : %v", finalURL, err))
			return
		}
		finalDomain := finalParsedURL.Hostname()
		finalPort := finalParsedURL.Port()
		if finalPort == "" {
			if finalParsedURL.Scheme == "https" {
				finalPort = "443"
			} else {
				finalPort = "80"
			}
		}

		if initialDomain != finalDomain || initialPort != finalPort {
			utils.SendError(results, inputURL, fmt.Sprintf("Target changed from %s:%s to %s:%s", initialDomain, initialPort, finalDomain, finalPort))
			return
		}

		data.Infos.Status_code = int(statusCode)
		data.Infos.Scheme = finalParsedURL.Scheme
		data.Url = initialURL

		c.launchChrome(structure.Response{}, data, initialURL, results)
	} else {

		// Handle with HTTP client without following redirects
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client := c.getClientCtx()
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {

			return http.ErrUseLastResponse
		}
		var TempResp structure.Response
		var errSSL error
		if port != "80" {
			request, _ := http.NewRequest("GET", urlDataPort, nil)
			resp, errSSL = Do(request, client, false)
		}
		if errSSL != nil || port == "80" {
			if port == "443" {
				errorContinue = false
			} else {
				request, _ := http.NewRequest("GET", urlDataPort, nil)
				resp, errPlain := Do(request, client, false)
				if errPlain != nil || resp == nil {
					errorContinue = false
				} else {
					data, TempResp, _ = c.DefineBasicMetric(data, resp)
					if data.Infos.Scheme == "" {
						data.Infos.Scheme = "http"
					}
					data.Url = urlDataPort
				}
			}
		} else {
			data, TempResp, _ = c.DefineBasicMetric(data, resp)
			if data.Infos.Scheme == "" {
				data.Infos.Scheme = "https"
			}
			data.Url = urlDataPort
		}

		if errorContinue {
			// Continue handling response data
			c.launchChrome(TempResp, data, inputURL, results)
		}
	}

}

func (c *Cmd) launchChrome(TempResp structure.Response, data structure.Data, urlData string, results chan structure.Data) {
	var err error
	if data.Infos.Location != "" {
		urlData = data.Infos.Location
	}

	// Obtenir des données DNS si disponibles
	dnsData, err := c.Dialer.GetDNSData(data.Infos.Data)
	if dnsData != nil && err == nil {
		data.Infos.Cname = dnsData.CNAME
	}
	analyseStruct := analyze.Analyze{}

	// Créer un contexte avec un délai pour éviter les tâches qui traînent
	ctxAlloc1, cancelCtx := context.WithTimeout(c.ChromeCtx, 60*time.Second)
	defer cancelCtx() // Assure la fermeture du contexte

	cloneCTX, cancelChromeCtx := chromedp.NewContext(ctxAlloc1)
	defer cancelChromeCtx() // Nettoyage du contexte Chrome

	// Écoute des événements cibles pour capturer des informations
	chromedp.ListenTarget(cloneCTX, func(ev interface{}) {
		if responseEvent, ok := ev.(*network.EventResponseReceived); ok {
			// Stocker les en-têtes dans TempResp.Headers
			if TempResp.Headers == nil {
				TempResp.Headers = make(map[string][]string)
			}
			for key, value := range responseEvent.Response.Headers {
				// Assurez-vous que la valeur est convertie en []string
				switch v := value.(type) {
				case string:
					TempResp.Headers[key] = []string{v}
				case []string:
					TempResp.Headers[key] = v
				}
			}

			// Traitement des types de documents
			switch responseEvent.Type {
			case "XHR":
				analyseStruct.XHRUrl = append(analyseStruct.XHRUrl, responseEvent.Response.URL)
			case "Stylesheet":
				// Traitement des feuilles de style (actuellement commenté)
			case "Script":
				// Traitement des scripts (actuellement commenté)
			}
		}

		// Gestion des dialogues JavaScript
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			go func() {
				if err := chromedp.Run(cloneCTX, page.HandleJavaScriptDialog(true)); err != nil {
					log.Printf("Error handling JavaScript dialog: %v", err)
				}
			}()
		}
	})

	// Tâches à exécuter dans Chrome
	var buf []byte
	err = chromedp.Run(cloneCTX,
		network.Enable(),
		network.SetCacheDisabled(true),
		chromedp.Navigate(urlData),
		chromedp.Title(&data.Infos.Title),
		chromedp.CaptureScreenshot(&buf),
		chromedp.ActionFunc(func(ctx context.Context) error {
			defer func() {
				if r := recover(); r != nil {
					utils.SendError(results, urlData, fmt.Sprintf("Recovered from panic in chromedp action: %v", r))
					return
				}
			}()
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
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			body, err := dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			if err == nil {
				reader := strings.NewReader(body)
				doc, err := goquery.NewDocumentFromReader(reader)
				if err != nil {
					log.Printf("Error parsing HTML document: %v", err)
				} else {
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

	// Vérification des erreurs de `chromedp.Run()`
	if err != nil {
		utils.SendError(results, urlData, fmt.Sprintf("Error in Chrome execution: %v", err))
		return
	}

	data.Infos.Technologies = technologies.DedupTechno(data.Infos.Technologies)
	if *c.Options.Screenshot != "" && len(buf) > 0 {
		imgTitle := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(urlData, ":", "_"), "/", ""), ".", "_")
		file, err := os.OpenFile(*c.Options.Screenshot+"/"+imgTitle+".png", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
		if err == nil {
			_, err = file.Write(buf)
			if err != nil {
				log.Printf("Error writing screenshot to file: %v", err)
			}
			file.Close()
		} else {
			log.Printf("Error opening screenshot file: %v", err)
		}
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

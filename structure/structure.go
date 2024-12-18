package structure

import (
	"net/url"
	"time"

	"github.com/projectdiscovery/cryptoutil"
)

type Technologie struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Cpe        string `json:"cpe,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

const WappazlyerRoot = "https://raw.githubusercontent.com/dochne/wappalyzer/master/src"
const LetterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var InterrestingKey = []string{"dns", "js", "meta", "text", "dom", "scripts", "html", "scriptSrc", "headers", "cookies", "url", "certIssuer", "xhr"}

type Host struct {
	Status_code    int           `json:"status_code"`
	Port           string        `json:"port"`
	Path           string        `json:"path"`
	Location       string        `json:"location,omitempty"`
	Title          string        `json:"title"`
	Scheme         string        `json:"scheme"`
	Data           string        `json:"data"`
	Response_time  time.Duration `json:"response_time"`
	Screenshot     string        `json:"screenshot_name,omitempty"`
	Technologies   []Technologie `json:"technologies"`
	Content_length int           `json:"content_length"`
	Content_type   string        `json:"content_type"`
	IP             string        `json:"ip"`
	Cname          []string      `json:"cname,omitempty"`
	CDN            string        `json:"cdn,omitempty"`
	CertVhost      []string      `json:"certvhost,omitempty"`
}
type Data struct {
	Url   string `json:"url"`
	Infos Host   `json:"infos"`
	Error string `json:"error,omitempty"`
}
type Options struct {
	Screenshot     *string
	Ports          *string
	Threads        *int
	Porttimeout    *int
	Resolvers      *string
	AmassInput     *bool
	FollowRedirect *bool
	ChromeTimeout  *int
	ChromeThreads  *int
	Report         *bool
	Proxy          *string
}
type WrapperOptions struct {
	Screenshot     string
	Ports          string
	Threads        int
	Porttimeout    int
	Resolvers      string
	FollowRedirect bool
	ChromeTimeout  int
	ChromeThreads  int
	Proxy          string
}

type Response struct {
	StatusCode    int
	Headers       map[string][]string
	Data          []byte
	ContentLength int
	Raw           string
	RawHeaders    string
	Words         int
	Lines         int
	TLSData       *cryptoutil.TLSData
	HTTP2         bool
	Pipeline      bool
	Duration      time.Duration
	URL           *url.URL   // Ajouter ce champ
	RedirectChain []*url.URL // Ajouter ce champ
}

type PortOpenByIp struct {
	IP        string
	Open_port []string
}

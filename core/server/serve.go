package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/utils"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kor44/gofilter"
)

func Serve() {

	defer pnc.PanicHndl()

	if domains.Config.Proxy.Cloudflare {
		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}

		service.Handler = http.HandlerFunc(Middleware)
		//service.SetKeepAlivesEnabled(false)

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	} else {
		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}
		serviceH := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":443",
			TLSConfig: &tls.Config{
				GetConfigForClient: firewall.Fingerprint,
				GetCertificate:     domains.GetCertificate,
				Renegotiation:      tls.RenegotiateOnceAsClient,
			},
			MaxHeaderBytes: 1 << 20,
		}

		service.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			firewall.Mutex.Lock()
			domainData := domains.DomainsData[r.Host]
			firewall.Mutex.Unlock()

			if domainData.Stage == 0 {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Unable to connect origin, please contact admin.")
				return
			}

			firewall.Mutex.Lock()
			domainData = domains.DomainsData[r.Host]
			domainData.TotalRequests++
			domains.DomainsData[r.Host] = domainData
			firewall.Mutex.Unlock()

			http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)
		})
		//service.SetKeepAlivesEnabled(false)

		serviceH.Handler = http.HandlerFunc(Middleware)
		//serviceH.SetKeepAlivesEnabled(false)

		go func() {
			defer pnc.PanicHndl()
			if err := serviceH.ListenAndServeTLS("", ""); err != nil {
				panic(err)
			}
		}()

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	}
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	cacheRes := 0
	reqIP := ""

	if req.Method != "POST" && proxy.CacheEnabled {

		domainSettings := req.Context().Value("domain").(domains.DomainSettings)
		messages := req.Context().Value("filter").(gofilter.Message)

		cacheRes = evalCache(domainSettings, messages)

		if cacheRes != 0 {
			var cacheResponse any
			cacheOk := false
			cacheKey := ""

			switch cacheRes {
			case proxy.CACHE_DEFAULT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_DEFAULT_STRICT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_CAREFUL:
				reqIP = strings.Split(req.RemoteAddr, ":")[0]
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_CAREFUL_STRICT:
				reqIP = strings.Split(req.RemoteAddr, ":")[0]
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_IGNORE_QUERY:
				cacheKey = req.Host + req.URL.Path
			case proxy.CACHE_QUERY:
				cacheKey = req.Host + req.URL.RawQuery
			case proxy.CACHE_CLIENTIP:
				reqIP = strings.Split(req.RemoteAddr, ":")[0]
				cacheKey = req.Host + reqIP
			default:
			}

			cacheResponse, cacheOk = domains.DomainsCache.Load(cacheKey)

			if cacheOk {
				cachedResp := cacheResponse.(domains.CacheResponse)

				//Check if cache is expired
				if cachedResp.Timestamp > int(time.Now().Unix()) {

					resp := &http.Response{
						StatusCode: cachedResp.Status,
						Header:     cachedResp.Headers,
						Body:       io.NopCloser(bytes.NewReader(cachedResp.Body)),
					}

					resp.Header.Set("proxy-cache", "HIT")
					return resp, nil
				}

				domains.DomainsCache.Delete(req.Host + req.URL.Path + req.URL.RawQuery)
			}
		}
	}

	//Use Proxy Read Timeout
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	//Use inbuild RoundTrip
	resp, err := transport.RoundTrip(req)

	//Connection to backend failed. Display error message
	if err != nil {
		errStrs := strings.Split(err.Error(), " ")
		errMsg := ""
		for _, str := range errStrs {
			if !strings.Contains(str, ".") && !strings.Contains(str, "/") && !(strings.Contains(str, "[") && strings.Contains(str, "]")) {
				errMsg += str + " "
			}
		}
		errPage := `
		<HTML><HEAD>
		<TITLE>Origin error.</TITLE>
		</HEAD><BODY>
		<H1>Web origin error.</H1>
		 
		<p>There was an issue connecting with your destination site.<P>
		Reference ID: Error: Er-Backend-Not-reachable-5xx<P>
		</BODY>
		</HTML>
		`

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(errPage)),
		}, nil
	}

	//Connection was successfull, got bad response tho
	if resp.StatusCode > 499 && resp.StatusCode < 600 {

		errPage := `
		<HTML><HEAD>
		<TITLE>User origin error.</TITLE>
		</HEAD><BODY>
		<H1>User origin error.</H1>
		 
		<p>There was an issue with your connection with your destination site.<P>
		Reference ID: Error: Returned-Bad-Response<P>
		</BODY>
		</HTML>
		`

		errBody, errErr := io.ReadAll(resp.Body)
		if errErr == nil && len(errBody) != 0 {
			errPage =
				`
				<HTML><HEAD>
				<TITLE>Web origin error.</TITLE>
				</HEAD><BODY>
				<H1>Web origin error.</H1>
				 
				<pThere was an issue connecting with your destination site.<P>
				Reference ID: Error: Er-Backend-Not-reachable-503<P>
				</BODY>
				</HTML>
				`
		}
		resp.Body.Close()

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(errPage)),
		}, nil
	}

	resp.Header.Set("proxy-cache", "MISS")

	if cacheRes != 0 && req.Method != "POST" && proxy.CacheEnabled {
		if resp.StatusCode < 300 || (resp.StatusCode < 500 && resp.StatusCode >= 400) {
			bodyBytes, bodyErr := io.ReadAll(resp.Body)

			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if bodyErr != nil {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Body:       io.NopCloser(strings.NewReader("BalooProxy: Failed to read responsebody of backend")),
				}, bodyErr
			}

			var cacheKey string
			switch cacheRes {
			case proxy.CACHE_DEFAULT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_DEFAULT_STRICT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_CAREFUL:
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_CAREFUL_STRICT:
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_IGNORE_QUERY:
				cacheKey = req.Host + req.URL.Path
			case proxy.CACHE_QUERY:
				cacheKey = req.Host + req.URL.RawQuery
			case proxy.CACHE_CLIENTIP:
				cacheKey = req.Host + reqIP
			default:
				panic("[ " + utils.RedText("Error") + " ]: " + utils.RedText("Cache Error: Failed to get correct cache resp"))
			}

			domains.DomainsCache.Store(cacheKey, domains.CacheResponse{
				Domain:    resp.Request.Host,
				Timestamp: int(time.Now().Unix()) + 3600, //Cache for an hour
				Status:    resp.StatusCode,
				Headers:   resp.Header,
				Body:      bodyBytes,
			})
		}
	}
	return resp, nil
}

func evalCache(domainSettings domains.DomainSettings, message gofilter.Message) int {
	for _, rule := range domainSettings.CacheRules {
		if rule.Filter.Apply(message) {
			switch rule.Action {
			case "BYPASS":
				return 0
			case "DEFAULT":
				return proxy.CACHE_DEFAULT
			case "DEFAULT_STRICT":
				return proxy.CACHE_DEFAULT_STRICT
			case "CAREFUL":
				return proxy.CACHE_CAREFUL
			case "CAREFUL_STRICT":
				return proxy.CACHE_CAREFUL_STRICT
			case "IGNORE_QUERY":
				return proxy.CACHE_IGNORE_QUERY
			case "QUERY":
				return proxy.CACHE_QUERY
			case "CLIENTIP":
				return proxy.CACHE_CLIENTIP
			default:
			}
		}
	}
	return 0
}

type RoundTripper struct {
}

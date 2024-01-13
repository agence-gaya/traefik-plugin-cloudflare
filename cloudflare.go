package traefik_plugin_cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
	"strings"
	"encoding/json"
	"log"
)

const (
	minRefresh     = 5 * time.Minute
	defaultRefresh = "24h"
)

type Config struct {
	TrustedCIDRs           []string `json:"trustedCIDRs,omitempty"`
	AllowedCIDRs           []string `json:"allowedCIDRs,omitempty"`
	RefreshInterval        string   `json:"refreshInterval,omitempty"`
	OverwriteRequestHeader bool     `json:"overwriteRequestHeader,omitempty"`
	AppendXForwardedFor     bool     `json:"appendXForwardedFor,omitempty"`
	Debug                  bool     `json:"debug,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TrustedCIDRs:           nil,
		AllowedCIDRs:			nil,
		RefreshInterval:        defaultRefresh,
		OverwriteRequestHeader: true,
		AppendXForwardedFor:    false,
		Debug:                  false,
	}
}

type Cloudflare struct {
	next                   http.Handler
	name                   string
	trustedChecker         ipChecker
	allowedChecker         ipChecker
	overwriteRequestHeader bool
	appendXForwardedFor    bool
	debug                  bool
}

// CFVisitorHeader definition for the header value.
type CFVisitorHeader struct {
	Scheme string `json:"scheme"`
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, errors.New("invalid config")
	}

	c := &Cloudflare{
		next:                   next,
		name:                   name,
		overwriteRequestHeader: config.OverwriteRequestHeader,
		appendXForwardedFor:    config.AppendXForwardedFor,
		debug:                  config.Debug,
	}

	if len(config.TrustedCIDRs) > 0 {
		cidrs := make([]*net.IPNet, 0, len(config.TrustedCIDRs))

		for _, c := range config.TrustedCIDRs {
			_, cidr, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted CIDR: %w", err)
			}

			cidrs = append(cidrs, cidr)
		}

		c.trustedChecker = &staticIPChecker{
			Cidrs: cidrs,
		}
	} else {
		ri, err := time.ParseDuration(config.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh interval: %w", err)
		}

		switch {
			case ri <= 0:
				ri = 0
			case ri < minRefresh:
				ri = minRefresh
		}

		checker := &cloudflareIPChecker{
			RefreshInterval: ri,
		}

		err = checker.Refresh(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh Cloudflare IPs: %w", err)
		}

		c.trustedChecker = checker
	}

	allowedCidrs := make([]*net.IPNet, 0, len(config.AllowedCIDRs))

	for _, c := range config.AllowedCIDRs {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed CIDR: %w", err)
		}

		allowedCidrs = append(allowedCidrs, cidr)
	}

	c.allowedChecker = &staticIPChecker{
		Cidrs: allowedCidrs,
	}

	return c, nil
}

func (c *Cloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	ipList := XForwardedIpValues(r)

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteAddrTrim := strings.TrimSpace(r.RemoteAddr)
   		if len(remoteAddrTrim) > 0 {
   			ipList = append(ipList, remoteAddrTrim)
   		}
   	} else {
		ipTrim := strings.TrimSpace(ip)
		if len(ipTrim) > 0 {
			ipList = append(ipList, ipTrim)
		}
	}

   	trusted := false
   	allowed := false

   	for i := 0; i < len(ipList); i++ {
   		sip := net.ParseIP(ipList[i])
		if sip == nil {
			if c.debug {
				log.Println(fmt.Sprintf("debug: bad ip %s", ipList[i]))
			}
			code := http.StatusBadRequest
			http.Error(w, fmt.Sprintf("cf:bad ip %s", ipList[i]), code)
			return
		}

		trustIp, err := c.trustedChecker.CheckIP(r.Context(), sip)
		if err != nil {
			if c.debug {
				log.Println(fmt.Errorf("debug: %w", err))
			}
			code := http.StatusInternalServerError
			http.Error(w, fmt.Sprintf("cf:%s", http.StatusText(code)), code)
			return
		}

		if trustIp {
			trusted = true
			allowed = true
           	break
        }

		allowIp, err := c.allowedChecker.CheckIP(r.Context(), sip)
		if err != nil && c.debug {
			log.Println(fmt.Errorf("debug: %w", err))
		}

		if allowIp {
        	allowed = true
        	break
        }
	}

	if !allowed {
		if c.debug {
			log.Println(fmt.Sprintf("debug: deny request from: %s", strings.Join(ipList, ",")))
		}
		code := http.StatusForbidden
		http.Error(w, fmt.Sprintf("cf:%s", http.StatusText(code)), code)
		return
	}

	if c.overwriteRequestHeader && trusted {
		err = overwriteRequestHeader(r, c.appendXForwardedFor)
		if err != nil {
			if c.debug {
				log.Println(fmt.Errorf("debug: %w", err))
			}
			code := http.StatusBadRequest
			http.Error(w, fmt.Sprintf("cf:%s", http.StatusText(code)), code)
			return
		}
	}

	c.next.ServeHTTP(w, r)
}

func overwriteRequestHeader(r *http.Request, appendXForwardedFor bool) error {
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		return errors.New("missing CF-Connecting-IP header")
	}

	if r.Header.Get("CF-Visitor") != "" {
    	var cfVisitorValue CFVisitorHeader
    	err := json.Unmarshal([]byte(r.Header.Get("CF-Visitor")), &cfVisitorValue);
    	if err == nil {
    	    r.Header.Set("X-Forwarded-Proto", cfVisitorValue.Scheme)
    	}
	}

	ipList := XForwardedIpValues(r)
	if appendXForwardedFor {
		ipList = append([]string{ip}, ipList...)
	} else {
		if len(ipList) == 0 {
			r.RemoteAddr = ip
			ipList = []string{ip}
		} else {
			ipList[0] = ip
		}
	}

    r.Header.Set("X-Forwarded-For", strings.Join(ipList, ", "))
	r.Header.Set("X-Real-Ip", ip)

	return nil
}

func XForwardedIpValues(r *http.Request) []string {
	var list []string

	xff := r.Header.Get("X-Forwarded-For")
   	xffs := strings.Split(xff, ",")

   	for i := 0; i < len(xffs); i++ {
   		xffsTrim := strings.TrimSpace(xffs[i])
   		if len(xffsTrim) > 0 {
   			list = append(list, xffsTrim)
    	}
    }

    return list
}

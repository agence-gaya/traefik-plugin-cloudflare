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
	RefreshInterval        string   `json:"refreshInterval,omitempty"`
	OverwriteRequestHeader bool     `json:"overwriteRequestHeader,omitempty"`
	Debug                  bool     `json:"debug,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TrustedCIDRs:           nil,
		RefreshInterval:        defaultRefresh,
		OverwriteRequestHeader: true,
		Debug:                  false,
	}
}

type Cloudflare struct {
	next                   http.Handler
	name                   string
	checker                ipChecker
	overwriteRequestHeader bool
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
		debug:                  config.Debug,
	}

	if len(config.TrustedCIDRs) > 0 {
		cidrs := make([]*net.IPNet, 0, len(config.TrustedCIDRs))

		for _, c := range config.TrustedCIDRs {
			_, cidr, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %w", err)
			}

			cidrs = append(cidrs, cidr)
		}

		c.checker = &staticIPChecker{
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

		c.checker = checker
	}

	return c, nil
}

func (c *Cloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ipList []string

	xff := r.Header.Get("X-Forwarded-For")
	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffsTrim := strings.TrimSpace(xffs[i])
		if len(xffsTrim) > 0 {
			ipList = append(ipList, xffsTrim)
		}
	}

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

   	allow := false

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

		allowIp, err := c.checker.CheckIP(r.Context(), sip)
		if err != nil {
			if c.debug {
				log.Println(fmt.Errorf("debug: %w", err))
			}
			code := http.StatusInternalServerError
			http.Error(w, fmt.Sprintf("cf:%s", http.StatusText(code)), code)
			return
		}

		if allowIp {
			allow = true
			break
		}
	}

	if !allow {
		if c.debug {
			log.Println(fmt.Sprintf("debug: deny request from: %s", strings.Join(ipList, ",")))
		}
		code := http.StatusForbidden
		http.Error(w, fmt.Sprintf("cf:%s", http.StatusText(code)), code)
		return
	}

	if c.overwriteRequestHeader {
		err = overwriteRequestHeader(r)
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

func overwriteRequestHeader(r *http.Request) error {
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		return errors.New("missing CF-Connecting-IP header")
	}

	// Permit to ipwhitelist middleware to match cloudflare client ip
	r.RemoteAddr = ip

	if r.Header.Get("CF-Visitor") != "" {
    	var cfVisitorValue CFVisitorHeader
    	err := json.Unmarshal([]byte(r.Header.Get("CF-Visitor")), &cfVisitorValue);
    	if err == nil {
    	    r.Header.Set("X-Forwarded-Proto", cfVisitorValue.Scheme)
    	}
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		r.Header.Set("X-Forwarded-For", ip + ", " + xff)
	} else {
		r.Header.Set("X-Forwarded-For", ip)
	}

	r.Header.Set("X-Real-Ip", ip)

	return nil
}
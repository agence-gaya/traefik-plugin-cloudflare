package traefik_plugin_cloudflare_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cloudflare "github.com/agence-gaya/traefik-plugin-cloudflare"
	"github.com/agence-gaya/traefik-plugin-cloudflare/internal"
	"github.com/stretchr/testify/require"
)

func TestCloudflare(t *testing.T) {
	log.SetOutput(io.Discard)

	t.Run("automatic CIDRs", func(t *testing.T) {
		dc := http.DefaultClient
		defer func() {
			http.DefaultClient = dc
		}()

		http.DefaultClient = &http.Client{
			Transport: &staticJsonTransport{
				Response: `{"result":{"ipv4_cidrs":["172.16.0.0/12"],"ipv6_cidrs":["2001:db8:2::/47"],"etag":"ffffffffffffffffffffffffffffffff"},"success":true,"errors":[],"messages":[]}`,
			},
		}

		cfg := cloudflare.CreateConfig()
		cfg.TrustedCIDRs = nil
		cfg.RefreshInterval = "0s"
		cfg.OverwriteRequestHeader = false
		cfg.Debug = true

		ctx := context.Background()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		handler, err := cloudflare.New(ctx, next, cfg, "cloudflare")
		require.NoError(t, err)

		t.Run("allowed ipv4", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("disallowed ipv4", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.15.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusForbidden, res.StatusCode)
		})

		t.Run("allowed ipv6", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "[2001:db8:2:2::1]:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("disallowed ipv6", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "[2001:db8:1:2::1]:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusForbidden, res.StatusCode)
		})
	})

	t.Run("automatic CIDRs periodic update", func(t *testing.T) {
		dc := http.DefaultClient
		defer func() {
			http.DefaultClient = dc
		}()

		now := ptime(time.Date(2010, time.January, 1, 0, 0, 0, 0, time.UTC))

		internal.Now = func() time.Time {
			return *now
		}

		http.DefaultClient = &http.Client{
			Transport: &staticJsonTransport{
				Response: `{"result":{"ipv4_cidrs":["172.16.0.0/12"],"ipv6_cidrs":["2001:db8:2::/47"],"etag":"ffffffffffffffffffffffffffffffff"},"success":true,"errors":[],"messages":[]}`,
			},
		}

		cfg := cloudflare.CreateConfig()
		cfg.TrustedCIDRs = nil
		cfg.RefreshInterval = "5m"
		cfg.OverwriteRequestHeader = false
		cfg.Debug = true

		ctx := context.Background()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		handler, err := cloudflare.New(ctx, next, cfg, "cloudflare")
		require.NoError(t, err)

		http.DefaultClient = &http.Client{
			Transport: &staticJsonTransport{
				Response: `{"result":null,"success":false,"errors":[{"code":1000,"message":"ERR"}],"messages":[]}`,
			},
		}

		t.Run("initially up-to-date", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("expired with error and cidrs", func(t *testing.T) {
			now = ptime(now.Add(time.Hour))

			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("up-to-date after error", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("expired with empty cidrs", func(t *testing.T) {
        	now = ptime(now.Add(time.Hour))

        	http.DefaultClient = &http.Client{
        		Transport: &staticJsonTransport{
        			Response: `{"result":{"ipv4_cidrs":[],"ipv6_cidrs":[],"etag":"ffffffffffffffffffffffffffffffff"},"success":true,"errors":[],"messages":[]}`,
        		},
        	}

        	req := &http.Request{
        		RemoteAddr: "172.16.1.1:42",
        	}

        	rr1 := httptest.NewRecorder()
        	handler.ServeHTTP(rr1, req)

        	res1 := rr1.Result()
            require.Equal(t, http.StatusForbidden, res1.StatusCode)

        	now = ptime(now.Add(time.Hour))

        	rr2 := httptest.NewRecorder()
            handler.ServeHTTP(rr2, req)

            res2 := rr2.Result()
        	require.Equal(t, http.StatusForbidden, res2.StatusCode)
        })

		t.Run("expired", func(t *testing.T) {
			now = ptime(now.Add(time.Hour))

			http.DefaultClient = &http.Client{
				Transport: &staticJsonTransport{
					Response: `{"result":{"ipv4_cidrs":["172.16.0.0/12"],"ipv6_cidrs":["2001:db8:2::/47"],"etag":"ffffffffffffffffffffffffffffffff"},"success":true,"errors":[],"messages":[]}`,
				},
			}

			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
	})

	t.Run("static CIDRs", func(t *testing.T) {
		cfg := cloudflare.CreateConfig()
		cfg.TrustedCIDRs = []string{"172.16.0.0/12", "2001:db8:2::/47"}
		cfg.OverwriteRequestHeader = false
		cfg.Debug = true

		ctx := context.Background()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		handler, err := cloudflare.New(ctx, next, cfg, "cloudflare")
		require.NoError(t, err)

		t.Run("allowed ipv4", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("disallowed ipv4", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.15.1.1:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusForbidden, res.StatusCode)
		})

		t.Run("allowed ipv6", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "[2001:db8:2:2::1]:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("disallowed ipv6", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "[2001:db8:1:2::1]:42",
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusForbidden, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Error(err)
			}
			require.Equal(t, "cf:Forbidden\n", string(body))
		})

		t.Run("allowed ipv4 xff", func(t *testing.T) {
            req := &http.Request{
                RemoteAddr: "10.10.10.10:42",
                Header: makeHeaders(map[string]string{
                	"X-Forwarded-For": "172.16.1.1, 1.1.1.1",
                }),
            }

            rr := httptest.NewRecorder()
            handler.ServeHTTP(rr, req)

            res := rr.Result()
            require.Equal(t, http.StatusOK, res.StatusCode)
        })

        t.Run("disallowed ipv4 xff", func(t *testing.T) {
            req := &http.Request{
	            RemoteAddr: "10.10.10.10:42",
                Header: makeHeaders(map[string]string{
                  	"X-Forwarded-For": "172.15.1.1, 1.1.1.1",
                }),
            }

            rr := httptest.NewRecorder()
            handler.ServeHTTP(rr, req)

            res := rr.Result()
            require.Equal(t, http.StatusForbidden, res.StatusCode)
        })

        t.Run("allowed ipv6 xff", func(t *testing.T) {
            req := &http.Request{
                RemoteAddr: "10.10.10.10:42",
                Header: makeHeaders(map[string]string{
                    "X-Forwarded-For": "2001:db8:2:2::1, 1.1.1.1",
                }),
            }

            rr := httptest.NewRecorder()
            handler.ServeHTTP(rr, req)

            res := rr.Result()
            require.Equal(t, http.StatusOK, res.StatusCode)
        })

        t.Run("disallowed ipv6 xff", func(t *testing.T) {
            req := &http.Request{
                RemoteAddr: "10.10.10.10:42",
                Header: makeHeaders(map[string]string{
                    "X-Forwarded-For": "2001:db8:1:2::1, 1.1.1.1",
                }),
            }

            rr := httptest.NewRecorder()
            handler.ServeHTTP(rr, req)

            res := rr.Result()
            require.Equal(t, http.StatusForbidden, res.StatusCode)
        })
	})

	t.Run("overwrite header request", func(t *testing.T) {
		cfg := cloudflare.CreateConfig()
		cfg.TrustedCIDRs = []string{"0.0.0.0/0"}
		cfg.OverwriteRequestHeader = true
		cfg.Debug = true

		ctx := context.Background()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		handler, err := cloudflare.New(ctx, next, cfg, "cloudflare")
		require.NoError(t, err)

		t.Run("valid", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
				Header: makeHeaders(map[string]string{
					"CF-Connecting-IP": "1.2.3.4",
					"CF-Visitor": "{\"scheme\":\"https\"}",
				}),
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			xff := strings.Join(req.Header.Values("X-Forwarded-For"), ",")
			require.Equal(t, "1.2.3.4", xff)

			xri := strings.Join(req.Header.Values("X-Real-Ip"), ",")
            require.Equal(t, "1.2.3.4", xri)

            xfp := strings.Join(req.Header.Values("X-Forwarded-Proto"), ",")
            require.Equal(t, "https", xfp)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("overwrite", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
				Header: makeHeaders(map[string]string{
					"CF-Connecting-IP": "1.2.3.4",
					"CF-Visitor": "{\"scheme\":\"https\"}",
					"X-Forwarded-For": "2.2.2.2, 3.3.3.3",
					"X-Real-Ip": "172.16.1.1",
				}),
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			xff := strings.Join(req.Header.Values("X-Forwarded-For"), ",")
			require.Equal(t, "1.2.3.4, 2.2.2.2, 3.3.3.3", xff)

			xri := strings.Join(req.Header.Values("X-Real-Ip"), ",")
            require.Equal(t, "1.2.3.4", xri)

            xfp := strings.Join(req.Header.Values("X-Forwarded-Proto"), ",")
            require.Equal(t, "https", xfp)

            res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("missing header", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "172.16.1.1:42",
				Header: makeHeaders(map[string]string{
					"X-Forwarded-For": "2.2.2.2, 3.3.3.3",
				}),
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusBadRequest, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			if err != nil {
            	t.Error(err)
            }
            require.Equal(t, "cf:Bad Request\n", string(body))
		})
	})

	t.Run("no overwrite header request", func(t *testing.T) {
		cfg := cloudflare.CreateConfig()
        cfg.TrustedCIDRs = []string{"0.0.0.0/0"}
        cfg.OverwriteRequestHeader = false
        cfg.Debug = true

        ctx := context.Background()
        next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

        handler, err := cloudflare.New(ctx, next, cfg, "cloudflare")
        require.NoError(t, err)

		t.Run("valid", func(t *testing.T) {
            req := &http.Request{
                RemoteAddr: "172.16.1.1:42",
                Header: makeHeaders(map[string]string{
                    "CF-Connecting-IP": "1.2.3.4",
                    "CF-Visitor": "{\"scheme\":\"https\"}",
                    "X-Forwarded-For": "2.2.2.2, 3.3.3.3",
                    "X-Forwarded-Proto": "http",
                    "X-Real-Ip": "10.10.10.10",
                }),
            }

            rr := httptest.NewRecorder()
            handler.ServeHTTP(rr, req)

            xff := strings.Join(req.Header.Values("X-Forwarded-For"), ",")
            require.Equal(t, "2.2.2.2, 3.3.3.3", xff)

            xri := strings.Join(req.Header.Values("X-Real-Ip"), ",")
            require.Equal(t, "10.10.10.10", xri)

            xfp := strings.Join(req.Header.Values("X-Forwarded-Proto"), ",")
            require.Equal(t, "http", xfp)

            res := rr.Result()
            require.Equal(t, http.StatusOK, res.StatusCode)
        })
	})

	t.Run("no overwrite allowed header request", func(t *testing.T) {
		cfg := cloudflare.CreateConfig()
		cfg.TrustedCIDRs = []string{"1.1.1.1/24"}
		cfg.AllowedCIDRs = []string{"2.2.2.2/24"}
		cfg.OverwriteRequestHeader = true
		cfg.Debug = true

		ctx := context.Background()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		handler, err := cloudflare.New(ctx, next, cfg, "cloudflare")
		require.NoError(t, err)

		t.Run("valid", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "10.10.10.10:42",
				Header: makeHeaders(map[string]string{
					"CF-Connecting-IP": "1.2.3.4",
					"CF-Visitor": "{\"scheme\":\"https\"}",
					"X-Forwarded-For": "2.2.2.2, 3.3.3.3",
					"X-Forwarded-Proto": "http",
					"X-Real-Ip": "10.10.10.10",
				}),
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			xff := strings.Join(req.Header.Values("X-Forwarded-For"), ",")
			require.Equal(t, "2.2.2.2, 3.3.3.3", xff)

			xri := strings.Join(req.Header.Values("X-Real-Ip"), ",")
			require.Equal(t, "10.10.10.10", xri)

			xfp := strings.Join(req.Header.Values("X-Forwarded-Proto"), ",")
			require.Equal(t, "http", xfp)

			res := rr.Result()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})

		t.Run("invalid", func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "10.10.10.10:42",
				Header: makeHeaders(map[string]string{
					"CF-Connecting-IP": "1.2.3.4",
					"CF-Visitor": "{\"scheme\":\"https\"}",
					"X-Forwarded-For": "3.3.3.3, 4.4.4.4",
					"X-Forwarded-Proto": "http",
					"X-Real-Ip": "10.10.10.10",
				}),
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			res := rr.Result()
			require.Equal(t, http.StatusForbidden, res.StatusCode)
		})
	})
}

func ptime(t time.Time) *time.Time {
	return &t
}

func makeHeaders(m map[string]string) http.Header {
	res := make(http.Header, len(m))

	for k, v := range m {
		res[http.CanonicalHeaderKey(k)] = []string{v}
	}

	return res
}

type staticJsonTransport struct {
	Response string
}

func (t *staticJsonTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString(t.Response)),
		Request:    r,
	}, nil
}

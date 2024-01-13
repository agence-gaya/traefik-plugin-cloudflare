# traefik-plugin-cloudflare

[![Tag Badge]][Tag] [![Go Version Badge]][Go Version] [![Build Badge]][Build] [![Go Report Card Badge]][Go Report Card]

Traefik plugin to handle traffic coming from Cloudflare.

## Features

* Only allow traffic originating from Cloudflare IP v4 and v6 
* Custom CIDRs list can be added to allow request not from CloudFlare 
* Refresh Clouflare CIDRs from Cloudflare API url https://api.cloudflare.com/client/v4/ips
* Handle `X-Forwarded-For` original header to allow Cloudflare request from a trusted revers proxy behind Traefik
* Rewrite requests `X-Forwarded-For` header with the user IP provided by `CF-Connecting-IP`
* Rewrite requests `X-Forwarded-Proto` header with the scheme provided by `CF-Visitor`
* Rewrite requests `X-Real-IP` header with the user IP provided by `CF-Connecting-IP`
* Rewrite RemoteAdress to permit Traefik ipwhitelist middleware to work on IP provided by `CF-Connecting-IP`

## Configuration

### Plugin options

|           Key            | Type            | Default |                                                                        Description                                                                        |
|:------------------------:|:---------------:|:-------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------:|
|      `trustedCIDRs`      | `[]string`      |  `[]`   |      Requests coming from a source not matching any of these CIDRs will be terminated with a 403. If empty, it is populated with Cloudflare's CIDRs.      |
|      `allowedCIDRs`      | `[]string`      |  `[]`   |          Requests coming from a source matching any of these CIDRs will not be terminated with a 403 and no overwrite of request header append.           |
|    `refreshInterval`     | `time.Duration` |  `24h`  |         When `trustedCIDRs` is empty, Cloudflare's CIDRs will be refreshed after this duration. Using a value of 0 seconds disables the refresh.          |
| `overwriteRequestHeader` | `bool`          | `true`  | When `true`, the request's header are rewrite. When `false` any header or traefik RemoteAddress are modified, filter only the request from Cloudflare IP. |
|         `debug`          | `bool`          | `false` |                                                           Output debug message in traefik log.                                                            |

### Traefik static configuration

```yaml
experimental:
  plugins:
    cloudflare:
      moduleName: github.com/agence-gaya/traefik-plugin-cloudflare
      version: v1.0.0
```

### Dynamic configuration

```yaml
http:
  middlewares:
    cloudflare:
      plugin:
        cloudflare:
          trustedCIDRs: []
          overwriteRequestHeader: true

  routers:
    foo-router:
      rule: Path(`/foo`)
      service: foo-service
      entryPoints:
        - web
      middlewares:
        - cloudflare
```

[Tag]: https://github.com/agence-gaya/traefik-plugin-cloudflare/tags
[Tag Badge]: https://img.shields.io/github/v/tag/agence-gaya/traefik-plugin-cloudflare?sort=semver
[Go Version]: /go.mod
[Go Version Badge]: https://img.shields.io/github/go-mod/go-version/agence-gaya/traefik-plugin-cloudflare
[Build]: https://github.com/agence-gaya/traefik-plugin-cloudflare/actions/workflows/test.yml
[Build Badge]: https://img.shields.io/github/actions/workflow/status/agence-gaya/traefik-plugin-cloudflare/test.yml
[Go Report Card]: https://goreportcard.com/report/github.com/agence-gaya/traefik-plugin-cloudflare
[Go Report Card Badge]: https://goreportcard.com/badge/github.com/agence-gaya/traefik-plugin-cloudflare

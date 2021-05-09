# DenyIP

DenyIP is a middleware plugin for [Traefik](https://github.com/traefik/traefik) which accepts IP addresses or IP address ranges and blocks requests originating from those IPs.

## Configuration

### Static

In the example below `fowardedHeaders.insecure` is enabled in order to allow the IP address to be available from proxied requests. In a production environment, you may want to consider using [`forwardedHeaders.trustedIPs`](https://docs.traefik.io/routing/entrypoints/#forwarded-headers)

```yaml
experimental:
  pilot:
    token: "xxxxx"
  plugins:
    denyip:
      modulename = "github.com/kevtainer/denyip"
      version = "v1.0.0"

entryPoints:
  http:
    address: ":80"
    forwardedHeaders:
      insecure: true
```

### Dynamic

To configure the `DenyIP` plugin you should create a [middleware](https://docs.traefik.io/middlewares/overview/) in your dynamic configuration as explained [here](https://docs.traefik.io/middlewares/overview/). The following example creates and uses the `denyip` middleware plugin to deny all requests originating from [Comcast](https://postmaster.comcast.net/dynamic-IP-ranges.html). `ipDenyList` will also accept non-CIDR ips, eg. `127.0.0.1`.

> Note: Providing invalid ip addresses or ranges in `ipDenyList` will cause an error and the plugin will not load.

```yaml
http:
  # Add the router
  routers:
    my-router:
      entryPoints:
      - http
      middlewares:
      - denyip
      service: service-foo
      rule: Path(`/foo`)

  # Add the middleware
  middlewares:
    denyip:
      plugin:
        ipDenyList:
          - 24.0.0.0/12
          - 24.16.0.0/13
          - 24.30.0.0/17
          - 24.34.0.0/16
          - 24.60.0.0/14
          - 24.91.0.0/16
          - 24.98.0.0/15
          - 24.118.0.0/16
          - 24.125.0.0/16
          - 24.126.0.0/15
          - 24.128.0.0/16
          - 24.129.0.0/17
          - 24.130.0.0/15
          - 24.147.0.0/16
          - 24.218.0.0/16
          - 24.245.0.0/18
          - 50.128.0.0/10
          - 65.34.128.0/17
          - 65.96.0.0/16
          - 66.30.0.0/15
          - 66.41.0.0/16
          - 66.56.0.0/18
          - 66.176.0.0/15
          - 66.229.0.0/16
          - 67.160.0.0/12
          - 67.176.0.0/15
          - 67.180.0.0/14
          - 67.184.0.0/13
          - 68.32.0.0/11
          - 68.80.0.0/14
          - 68.84.0.0/16
          - 69.136.0.0/15
          - 69.138.0.0/16
          - 69.139.0.0/17
          - 69.140.0.0/14
          - 69.180.0.0/15
          - 69.242.0.0/15
          - 69.244.0.0/14
          - 69.248.0.0/14
          - 69.253.0.0/16
          - 69.254.0.0/15
          - 71.56.0.0/13
          - 71.192.0.0/12
          - 71.224.0.0/12
          - 73.0.0.0/8
          - 75.64.0.0/13
          - 75.72.0.0/15
          - 75.74.0.0/16
          - 75.75.0.0/17
          - 75.75.128.0/18
          - 76.16.0.0/12
          - 76.97.0.0/16
          - 76.98.0.0/15
          - 76.100.0.0/14
          - 76.104.0.0/13
          - 76.112.0.0/12
          - 98.192.0.0/13
          - 98.200.0.0/14
          - 98.204.0.0/16
          - 98.206.0.0/15
          - 98.208.0.0/12
          - 98.224.0.0/12
          - 98.240.0.0/16
          - 98.242.0.0/15
          - 98.244.0.0/14
          - 98.248.0.0/13
          - 107.2.0.0/15
          - 107.4.0.0/15
          - 174.48.0.0/12

  # Add the service
  services:
    service-foo:
      loadBalancer:
        servers:
        - url: http://localhost:5000/
        passHostHeader: false
```
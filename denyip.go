// Package denyip - middleware for denying request based on IP.
package denyip

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	xForwardedFor = "X-Forwarded-For"
)

// Checker allows to check that addresses are in a denied IPs.
type Checker struct {
	denyIPs    []*net.IP
	denyIPsNet []*net.IPNet
}

// Config the plugin configuration.
type Config struct {
	IPDenyList []string `json:"ipDenyList,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// DenyIP plugin.
type denyIP struct {
	next    http.Handler
	checker *Checker
	name    string
}

// New creates a new DenyIP plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	checker, err := NewChecker(config.IPDenyList)
	if err != nil {
		return nil, err
	}

	return &denyIP{
		checker: checker,
		next:    next,
		name:    name,
	}, nil
}

func (a *denyIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqIPAddr := a.GetRemoteIP(req)
	reqIPAddrLenOffset := len(reqIPAddr) - 1

	for i := reqIPAddrLenOffset; i >= 0; i-- {
		isBlocked, err := a.checker.Contains(reqIPAddr[i])
		if err != nil {
			log.Printf("%v", err)
		}

		if isBlocked {
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}

	a.next.ServeHTTP(rw, req)
}

// GetRemoteIP returns a list of IPs that are associated with this request.
func (a *denyIP) GetRemoteIP(req *http.Request) []string {
	var ipList []string

	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")

	log.Printf("xff: %v", xff)
	log.Printf("xffs: %v", xffs)

	for i := len(xffs) - 1; i >= 0; i-- {
		ipList = append(ipList, strings.TrimSpace(xffs[i]))
	}

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Printf("req.RemoteAddr: %v", req.RemoteAddr)
		ipList = append(ipList, strings.TrimSpace(req.RemoteAddr))
	} else {
		log.Printf("ip: %v", ip)
		ipList = append(ipList, strings.TrimSpace(ip))
	}

	return ipList
}

// NewChecker builds a new Checker given a list of CIDR-Strings to trusted IPs.
func NewChecker(trustedIPs []string) (*Checker, error) {
	if len(trustedIPs) == 0 {
		return nil, errors.New("no trusted IPs provided")
	}

	checker := &Checker{}

	for _, ipMask := range trustedIPs {
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.denyIPs = append(checker.denyIPs, &ipAddr)
		} else {
			_, ipAddr, err := net.ParseCIDR(ipMask)
			if err != nil {
				return nil, fmt.Errorf("parsing CIDR trusted IPs %s: %w", ipAddr, err)
			}
			checker.denyIPsNet = append(checker.denyIPsNet, ipAddr)
		}
	}

	return checker, nil
}

// IsDenied checks if provided request is denied by the denied IPs.
func (ip *Checker) IsDenied(addr string) error {
	var invalidMatches []string

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	ok, err := ip.Contains(host)
	if err != nil {
		return err
	}

	if !ok {
		invalidMatches = append(invalidMatches, addr)
		return fmt.Errorf("%q matched none of the trusted IPs", strings.Join(invalidMatches, ", "))
	}

	return nil
}

// Contains checks if provided address is in the denied IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("empty IP address")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("unable to parse address: %s: %w", addr, err)
	}

	return ip.ContainsIP(ipAddr), nil
}

// ContainsIP checks if provided address is in the trusted IPs.
func (ip *Checker) ContainsIP(addr net.IP) bool {
	for _, deniedIP := range ip.denyIPs {
		if deniedIP.Equal(addr) {
			return true
		}
	}

	for _, denyNet := range ip.denyIPsNet {
		if denyNet.Contains(addr) {
			return true
		}
	}

	return false
}

func parseIP(addr string) (net.IP, error) {
	userIP := net.ParseIP(addr)
	if userIP == nil {
		return nil, fmt.Errorf("can't parse IP from address %s", addr)
	}

	return userIP, nil
}

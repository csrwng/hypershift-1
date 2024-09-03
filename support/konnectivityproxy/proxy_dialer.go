package konnectivityproxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/proxy"
)

func init() {
	// The proxy package only interprets the ALL_PROXY variable.
	os.Setenv("ALL_PROXY", os.Getenv("HTTPS_PROXY"))
	// The proxy itself might be using either http or https, so we have to
	// register both dialers.
	proxy.RegisterDialerType("http", newHTTPDialer)
	proxy.RegisterDialerType("https", newHTTPDialer)
}

func newHTTPDialer(proxyURL *url.URL, forwardDialer proxy.Dialer) (proxy.Dialer, error) {
	return &httpProxyDialer{proxyURL: proxyURL, forwardDial: forwardDialer.Dial}, nil
}

// Everything below is a copied from https://github.com/fasthttp/websocket/blob/2f8e79d2aac1e8e5a06518870e872b15608cea90/proxy.go
// as the golang.org/x/net/proxy package only supports socks5 proxies, but does allow registering additional protocols.
type httpProxyDialer struct {
	proxyURL    *url.URL
	forwardDial func(network, addr string) (net.Conn, error)
}

func (hpd *httpProxyDialer) Dial(network string, addr string) (net.Conn, error) {
	fmt.Println("httpProxyDialer Dial")
	hostPort, _ := hostPortNoPort(hpd.proxyURL)
	fmt.Println("hostPort", hostPort)
	fmt.Println("forward dialing", "network", network, "hostPort", hostPort, "dialer", fmt.Sprintf("%T", hpd.forwardDial))
	conn, err := hpd.forwardDial(network, hostPort)
	if err != nil {
		fmt.Println("Error occurred with forward dial", err)
		return nil, err
	}
	fmt.Println("Forward dial connection established")

	connectHeader := make(http.Header)
	if user := hpd.proxyURL.User; user != nil {
		proxyUser := user.Username()
		if proxyPassword, passwordSet := user.Password(); passwordSet {
			credential := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPassword))
			connectHeader.Set("Proxy-Authorization", "Basic "+credential)
		}
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: connectHeader,
	}
	fmt.Println("Assembled connection request", connectReq)

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response. It's OK to use and discard buffered reader here becaue
	// the remote server does not speak until spoken to.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		fmt.Println("Error returned from ReadResponse", err)
		conn.Close()
		return nil, err
	}
	fmt.Println("Read response was successful")

	if resp.StatusCode != 200 {
		fmt.Println("Status code is not success", resp.StatusCode)
		conn.Close()
		f := strings.SplitN(resp.Status, " ", 2)
		return nil, errors.New(f[1])
	}
	fmt.Println("Connection established successfully")
	return conn, nil
}

func hostPortNoPort(u *url.URL) (hostPort, hostNoPort string) {
	hostPort = u.Host
	hostNoPort = u.Host
	if i := strings.LastIndex(u.Host, ":"); i > strings.LastIndex(u.Host, "]") {
		hostNoPort = hostNoPort[:i]
	} else {
		switch u.Scheme {
		case "wss":
			hostPort += ":443"
		case "https":
			hostPort += ":443"
		default:
			hostPort += ":80"
		}
	}
	return hostPort, hostNoPort
}

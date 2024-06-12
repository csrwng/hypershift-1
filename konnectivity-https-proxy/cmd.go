package konnectivityhttpsproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/openshift/hypershift/pkg/version"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"
	"sigs.k8s.io/apiserver-network-proxy/pkg/util"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func NewStartCommand() *cobra.Command {
	l := log.Log.WithName("konnectivity-https-proxy")
	log.SetLogger(zap.New(zap.UseDevMode(true), zap.JSONEncoder(func(o *zapcore.EncoderConfig) {
		o.EncodeTime = zapcore.RFC3339TimeEncoder
	})))
	cmd := &cobra.Command{
		Use:   "konnectivity-https-proxy",
		Short: "Runs the konnectivity https proxy server.",
		Long: ` Runs the konnectivity https proxy server.
		This proxy accepts request and tunnels them through the designated Konnectivity Server.`,
	}

	var proxyHostname string
	var proxyPort int
	var servingPort int
	var caCertPath string
	var clientCertPath string
	var clientKeyPath string

	cmd.Flags().StringVar(&proxyHostname, "konnectivity-hostname", "konnectivity-server-local", "The hostname of the konnectivity service.")
	cmd.Flags().IntVar(&proxyPort, "konnectivity-port", 8090, "The konnectivity port that https proxy should connect to.")
	cmd.Flags().IntVar(&servingPort, "serving-port", 8090, "The port that https proxy should serve on.")

	cmd.Flags().StringVar(&caCertPath, "ca-cert-path", "/etc/konnectivity/proxy-ca/ca.crt", "The path to the konnectivity client's ca-cert.")
	cmd.Flags().StringVar(&clientCertPath, "tls-cert-path", "/etc/konnectivity/proxy-client/tls.crt", "The path to the konnectivity client's tls certificate.")
	cmd.Flags().StringVar(&clientKeyPath, "tls-key-path", "/etc/konnectivity/proxy-client/tls.key", "The path to the konnectivity client's private key.")

	cmd.Run = func(cmd *cobra.Command, args []string) {
		l.Info("Starting proxy", "version", version.String())
		dialFunc := dialFunc(caCertPath, clientCertPath, clientKeyPath, proxyHostname, proxyPort)
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		proxy.ConnectDial = dialFunc
		err := http.ListenAndServe(fmt.Sprintf(":%d", servingPort), proxy)
		if err != nil {
			panic(err.Error())
		}
	}

	return cmd
}

// dialFunc returns the appropriate dial function based on user and proxy setting configurations
func dialFunc(caCertPath string, clientCertPath string, clientKeyPath string, proxyHostname string, proxyPort int) func(network string, addr string) (net.Conn, error) {
	return func(network string, requestAddress string) (net.Conn, error) {
		// get a TLS config based on x509 certs
		tlsConfig, err := util.GetClientTLSConfig(caCertPath, clientCertPath, clientKeyPath, proxyHostname, nil)
		if err != nil {
			return nil, err
		}

		// connect to the proxy address and get a TLS connection
		proxyAddress := fmt.Sprintf("%s:%d", proxyHostname, proxyPort)
		proxyConn, err := tls.Dial("tcp", proxyAddress, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("dialing proxy %q failed: %v", proxyAddress, err)
		}
		connectString := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", requestAddress, "127.0.0.1")
		_, err = fmt.Fprintf(proxyConn, "%s", connectString)
		if err != nil {
			return nil, err
		}

		// read HTTP response and return the connection
		br := bufio.NewReader(proxyConn)
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via proxy %s failed: %v",
				requestAddress, proxyAddress, err)
		}
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("proxy error from %s while dialing %s: %v", proxyAddress, requestAddress, res.Status)
		}
		// It's safe to discard the bufio.Reader here and return the original TCP conn directly because we only use this
		// for TLS. In TLS, the client speaks first, so we know there's no unbuffered data, but we can double-check.
		if br.Buffered() > 0 {
			return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT proxy %q",
				br.Buffered(), proxyAddress)
		}
		return proxyConn, nil
	}
}

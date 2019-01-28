// remoteu2f-proxy is the http+grpc server for remoteu2f.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	// Enable profiling via HTTP.
	// We will only use this if --debug_addr is given.
	_ "net/http/pprof"

	"github.com/golang/glog"
)

// Command-line flags.
var (
	baseURL = flag.String("base_url", "",
		"base URL to send the clients (e.g. https://domain:8800); "+
			"must be https and not have a trailing '/'")

	httpAddr = flag.String("http_addr", ":8800",
		"address where to listen for HTTP requests")
	grpcAddr = flag.String("grpc_addr", ":8801",
		"address where to listen for GPRC requests")
	debugAddr = flag.String("debug_addr", "",
		"address where to listen for debug/trace/profile HTTP requests")

	tlsCert = flag.String("tls_cert", "cert.pem",
		"file containing the TLS certificate to use")
	tlsKey = flag.String("tls_key", "key.pem",
		"file containing the TLS key to use")
	grpcCert = flag.String("tls_cert_grpc", "",
		"if set, use this certificate for GRPC instead of --tls_cert")
	grpcKey = flag.String("tls_key_grpc", "",
		"if set, use this key for GRPC instead of --tls_key")

	tokenFile = flag.String("token_file", "tokens",
		"file containing the valid client access tokens")
)

func validateBaseURL(s string) error {
	u, err := url.Parse(*baseURL)
	if err != nil {
		return fmt.Errorf("malformed url: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme MUST be 'https'")
	}
	if u.Path != "" {
		return fmt.Errorf("path MUST be empty (not even a trailing '/')")
	}

	return nil
}

func getValidTokens(path string) (map[string]bool, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	tokens := map[string]bool{}
	for _, t := range strings.Split(string(contents), "\n") {
		// Remove empty lines, and make sure all tokens have a minimum lenght.
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) < 10 {
			return nil, fmt.Errorf(
				"token %q too short (minimum lenght: 10)", t)
		}

		tokens[t] = true
	}

	return tokens, nil
}

func main() {
	flag.Parse()

	// We have strict requirements on baseURL because we use it as the appID.
	if err := validateBaseURL(*baseURL); err != nil {
		glog.Fatalf("invalid --base_url: %s", err)
	}

	validTokens, err := getValidTokens(*tokenFile)
	if err != nil {
		glog.Fatalf("error reading token file: %s", err)
	}

	s := NewServer()
	s.BaseURL = *baseURL
	s.HTTPAddr = *httpAddr
	s.GRPCAddr = *grpcAddr
	s.ValidTokens = validTokens

	s.HTTPCert = *tlsCert
	s.HTTPKey = *tlsKey
	s.GRPCCert = *tlsCert
	s.GRPCKey = *tlsKey
	if *grpcCert != "" {
		s.GRPCCert = *grpcCert
	}
	if *grpcKey != "" {
		s.GRPCKey = *grpcKey
	}

	if *debugAddr != "" {
		// Launch the default HTTP server at the given address.
		// This is the one pprof and grpc register automatically against.
		go func() {
			glog.Infof("Debug HTTP listening on %s", *debugAddr)
			err := http.ListenAndServe(*debugAddr, nil)
			glog.Fatalf("Debug HTTP exiting: %s", err)
		}()
	}

	s.ListenAndServe()
}

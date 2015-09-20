package main

// Embed the html and js files we need.
//go:generate go run tools/embed.go to_embed/*.html to_embed/*.js

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "blitiri.com.ar/go/remoteu2f/internal/proto"
)

// randomID generates a random ID to use as part of the URL and to identify a
// single operation.
func randomID() (string, error) {
	// 64 bit from crypto/rand should be enough for our purposes.
	// These are reasonably short-lived (2m) and we have rate limiting.
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// We treat Registrations and Authentication requests the same.
type PendingOp struct {
	// JSON that came in the Prepare message.
	prepared []byte

	// Message for the user, from the Prepare message.
	msg string

	// Request type, from the Prepare message.
	rtype pb.Prepare_RType

	// Channel we use to send the reply.
	reply chan []byte
}

type Server struct {
	BaseURL     string
	HTTPAddr    string
	GRPCAddr    string
	ValidTokens map[string]bool

	HTTPCert string
	HTTPKey  string
	GRPCCert string
	GRPCKey  string

	mu  sync.Mutex
	ops map[string]*PendingOp

	ratelimiter *RateLimiter
}

func NewServer() *Server {
	// Rate-limit requests to 50/s.
	// TODO: Make this configurable.
	rl := &RateLimiter{
		Interval: 1 * time.Second,
		MaxCount: 50,
	}

	return &Server{
		ops:         map[string]*PendingOp{},
		ratelimiter: rl,
	}
}

func (s *Server) removeOp(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.ops[key]
	if !ok {
		return
	}

	delete(s.ops, key)
	close(op.reply)
}

func (s *Server) removeOpAfter(key string, after time.Duration) {
	<-time.After(after)
	s.removeOp(key)
}

func (s *Server) getOp(key string) (*PendingOp, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.ops[key]
	return op, ok
}

func (s *Server) checkOauth(ctx context.Context) error {
	md, ok := metadata.FromContext(ctx)
	if !ok || md == nil {
		return grpc.Errorf(codes.PermissionDenied, "MD not found")
	}

	for _, tokenMD := range md["authorization"] {
		// tokenMD is: <type> SP <token>. Extract the token
		ps := strings.SplitN(tokenMD, " ", 2)
		if len(ps) != 2 {
			return grpc.Errorf(codes.PermissionDenied, "invalid token format")
		}
		token := ps[1]

		if _, ok := s.ValidTokens[token]; ok {
			return nil
		}
	}

	return grpc.Errorf(codes.PermissionDenied, "token not authorized")
}

func (s *Server) PrepareOp(ctx context.Context, p *pb.Prepare) (*pb.Url, error) {
	if !s.ratelimiter.Allowed() {
		return nil, grpc.Errorf(codes.Unavailable, "rate limited")
	}

	if err := s.checkOauth(ctx); err != nil {
		return nil, err
	}

	key, err := randomID()
	if err != nil {
		return nil, err
	}

	op := &PendingOp{
		prepared: p.Json,
		msg:      p.Msg,
		rtype:    p.Rtype,

		// Buffered channel makes us not block if the grpc client goes away.
		reply: make(chan []byte, 1),
	}

	s.mu.Lock()
	s.ops[key] = op
	s.mu.Unlock()

	// We don't expect to have enough pending operations for the number of
	// goroutines to be a problem.
	go s.removeOpAfter(key, 3*time.Minute)

	return &pb.Url{
		Url: s.BaseURL + "/" + key + "/",
		Key: key,
	}, nil
}

func (s *Server) GetOpResponse(ctx context.Context, url *pb.Url) (*pb.Response, error) {
	if !s.ratelimiter.Allowed() {
		return nil, grpc.Errorf(codes.Unavailable, "rate limited")
	}

	// We could be more paranoid and check against the token that prepared the
	// operation, but this is good enough for now.
	if err := s.checkOauth(ctx); err != nil {
		return nil, err
	}

	op, ok := s.getOp(url.Key)
	if !ok {
		return nil, grpc.Errorf(codes.FailedPrecondition, "key not found")
	}

	reply, ok := <-op.reply
	if !ok {
		return nil, grpc.Errorf(codes.DeadlineExceeded,
			"timed out waiting for reply")
	}

	// Remove the data once we've sent a reply.
	s.removeOp(url.Key)

	return &pb.Response{reply}, nil
}

func (s *Server) GetAppID(ctx context.Context, _ *pb.Void) (*pb.Url, error) {
	if !s.ratelimiter.Allowed() {
		return nil, grpc.Errorf(codes.Unavailable, "rate limited")
	}

	if err := s.checkOauth(ctx); err != nil {
		return nil, err
	}

	r := &pb.Url{
		Key: "",
		Url: s.BaseURL,
	}
	return r, nil
}

func keyFromRequest(r *http.Request) string {
	vs := mux.Vars(r)
	return vs["key"]
}

var registerTmpl = template.Must(
	template.New("register").Parse(register_html))
var authenticateTmpl = template.Must(
	template.New("authenticate").Parse(authenticate_html))

// Serve the key-specific index.
func (s *Server) IndexHandler(w http.ResponseWriter, r *http.Request) {
	tr := trace.New("http", "index")
	defer tr.Finish()

	if !s.ratelimiter.Allowed() {
		tr.LazyPrintf("rate limited")
		tr.SetError()
		http.Error(w, "too many requests", 429)
		return
	}

	key := keyFromRequest(r)
	tr.LazyPrintf("key: %s", key)
	op, ok := s.getOp(key)
	if !ok {
		tr.LazyPrintf("404 error")
		tr.SetError()
		http.NotFound(w, r)
		return
	}

	var err error
	data := struct {
		Message string
		Request string
	}{
		op.msg,
		string(op.prepared),
	}
	switch op.rtype {
	case pb.Prepare_REGISTER:
		err = registerTmpl.Execute(w, data)
	case pb.Prepare_AUTHENTICATE:
		err = authenticateTmpl.Execute(w, data)
	default:
		err = fmt.Errorf("unknown operation type %v", op.rtype)
	}

	if err != nil {
		tr.LazyPrintf("render error: %v", err)
		tr.SetError()
		http.Error(w, "error rendering", http.StatusBadRequest)
		return
	}
}

// StaticHandler returns an HTTP handler for the given path and content.
func (s *Server) StaticHandler(path, content string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tr := trace.New("http", path)
		defer tr.Finish()

		if !s.ratelimiter.Allowed() {
			tr.LazyPrintf("rate limited")
			tr.SetError()
			http.Error(w, "too many requests", 429)
			return
		}
		w.Write([]byte(content))
	}
}

// Common handler for both javascript responses.
func (s *Server) HTTPResponse(w http.ResponseWriter, r *http.Request) {
	tr := trace.New("http", "response")
	defer tr.Finish()

	if !s.ratelimiter.Allowed() {
		tr.LazyPrintf("rate limited")
		tr.SetError()
		http.Error(w, "too many requests", 429)
		return
	}

	key := keyFromRequest(r)
	tr.LazyPrintf("key: %s", key)
	op, ok := s.getOp(key)
	if !ok {
		tr.LazyPrintf("404 error")
		tr.SetError()
		http.NotFound(w, r)
		return
	}

	buf := make([]byte, 4*1024)
	n, err := r.Body.Read(buf)

	if err != nil && err != io.EOF {
		tr.LazyPrintf("400 error reading body: %v", err)
		tr.SetError()
		http.Error(w, "error reading body", http.StatusBadRequest)
		return
	}

	op.reply <- buf[:n]

	w.Write([]byte("success"))
}

func (s *Server) ListenAndServe() {
	// Prepare and launch the HTTP server.
	r := mux.NewRouter()
	r.HandleFunc("/{key}/", s.IndexHandler)
	r.HandleFunc("/{key}/response", s.HTTPResponse)
	r.HandleFunc("/{key}/u2f_api.js",
		s.StaticHandler("u2f_api.js", u2f_api_js))
	r.HandleFunc("/{key}/remoteu2f.js",
		s.StaticHandler("remoteu2f.js", remoteu2f_js))
	httpServer := http.Server{
		Addr:    s.HTTPAddr,
		Handler: r,
	}

	go func() {
		glog.Infof("HTTP listening on %s", s.HTTPAddr)
		err := httpServer.ListenAndServeTLS(s.HTTPCert, s.HTTPKey)
		glog.Fatalf("HTTP exiting: %s", err)
	}()

	// And now the GRPC server.
	lis, err := net.Listen("tcp", s.GRPCAddr)
	if err != nil {
		glog.Errorf("failed to listen: %v", err)
		return
	}

	ta, err := credentials.NewServerTLSFromFile(s.GRPCCert, s.GRPCKey)
	if err != nil {
		glog.Errorf("failed to create TLS transport auth: %v", err)
		return
	}

	grpcServer := grpc.NewServer(grpc.Creds(ta))
	pb.RegisterRemoteU2FServer(grpcServer, s)

	glog.Infof("GRPC listening on %s", s.GRPCAddr)
	err = grpcServer.Serve(lis)
	glog.Infof("GRPC exiting: %s", err)
}

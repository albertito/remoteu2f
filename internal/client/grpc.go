package client

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tstranex/u2f"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"

	pb "blitiri.com.ar/go/remoteu2f/internal/proto"
)

type RemoteU2FClient struct {
	c pb.RemoteU2FClient
}

func GRPCClient(addr, token, caFile string) (*RemoteU2FClient, error) {
	var err error
	var tCreds credentials.TransportCredentials
	if caFile == "" {
		tCreds = credentials.NewClientTLSFromCert(nil, "")
	} else {
		tCreds, err = credentials.NewClientTLSFromFile(caFile, "")
		if err != nil {
			return nil, fmt.Errorf("error reading CA file: %s", err)
		}
	}

	t := oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
	}
	rpcCreds := oauth.NewOauthAccess(&t)

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(tCreds),
		grpc.WithPerRPCCredentials(rpcCreds),
		grpc.WithBlock(),
		grpc.WithTimeout(30*time.Second))
	if err != nil {
		return nil, fmt.Errorf("error connecting to server: %s", err)
	}

	c := pb.NewRemoteU2FClient(conn)
	return &RemoteU2FClient{c}, nil
}

func (c *RemoteU2FClient) GetAppID() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r, err := c.c.GetAppID(ctx, &pb.Void{})
	if err != nil {
		return "", err
	}

	return r.Url, nil
}

type PendingRegister struct {
	Key       *pb.Url
	challenge *u2f.Challenge
}

func (c *RemoteU2FClient) PrepareRegister(msg, appID string) (*PendingRegister, error) {
	var trustedFacets = []string{appID}

	challenge, err := u2f.NewChallenge(appID, trustedFacets)
	if err != nil {
		return nil, fmt.Errorf("u2f.NewChallenge error: %v", err)
	}

	j, err := json.Marshal(challenge.RegisterRequest())
	if err != nil {
		return nil, fmt.Errorf("json marshalling error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	key, err := c.c.PrepareOp(ctx, &pb.Prepare{j, msg, pb.Prepare_REGISTER})
	if err != nil {
		return nil, fmt.Errorf("error preparing: %v", err)
	}

	return &PendingRegister{key, challenge}, nil
}

func (c *RemoteU2FClient) CompleteRegister(p *PendingRegister) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := c.c.GetOpResponse(ctx, p.Key)
	if err != nil {
		return nil, fmt.Errorf("error registering: %v", err)
	}

	var regResp u2f.RegisterResponse
	if err := json.Unmarshal(resp.Json, &regResp); err != nil {
		return nil, fmt.Errorf("invalid response: %s", err)
	}

	config := u2f.Config{
		// Unfortunately we don't have the attestation certs of many keys,
		// so skip the check for now.
		SkipAttestationVerify: true,
	}

	reg, err := u2f.Register(regResp, *p.challenge, &config)
	if err != nil {
		return nil, fmt.Errorf("u2f.Register error: %v", err)
	}

	// We save the marshalled registration object, which we use later to get
	// it back for authorization purposes.
	return reg.MarshalBinary()
}

type PendingAuth struct {
	Key *pb.Url

	// Registrations we sent auth requests for.
	regs []*u2f.Registration

	// Challenges matching each registration.
	challenges []*u2f.Challenge
}

func (c *RemoteU2FClient) PrepareAuthentication(msg, appID string, marshalledRegs [][]byte) (
	*PendingAuth, error) {

	var trustedFacets = []string{appID}

	pa := &PendingAuth{}
	signReqs := []*u2f.SignRequest{}

	// Generate one signature request for each registration.
	for _, mreg := range marshalledRegs {
		reg := &u2f.Registration{}
		err := reg.UnmarshalBinary(mreg)
		if err != nil {
			return nil, fmt.Errorf("u2f.ParseRegistration: %v\n", err)
		}

		// Can/should we reuse the challenge for all the registrations?
		challenge, err := u2f.NewChallenge(appID, trustedFacets)
		if err != nil {
			return nil, fmt.Errorf("u2f.NewChallenge error: %v", err)
		}

		sr := challenge.SignRequest(*reg)
		signReqs = append(signReqs, sr)

		pa.challenges = append(pa.challenges, challenge)
		pa.regs = append(pa.regs, reg)
	}

	j, err := json.Marshal(signReqs)
	if err != nil {
		return nil, fmt.Errorf("json marshalling error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	key, err := c.c.PrepareOp(
		ctx, &pb.Prepare{j, msg, pb.Prepare_AUTHENTICATE})
	if err != nil {
		return nil, fmt.Errorf("error preparing: %v", err)
	}

	pa.Key = key

	return pa, nil
}

func (c *RemoteU2FClient) CompleteAuthentication(pa *PendingAuth) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := c.c.GetOpResponse(ctx, pa.Key)
	if err != nil {
		return fmt.Errorf("error authenticating: %v", err)
	}

	var signResp u2f.SignResponse
	if err := json.Unmarshal(resp.Json, &signResp); err != nil {
		return fmt.Errorf("invalid response: %s", err)
	}

	for i, reg := range pa.regs {
		// TODO: support counters.
		_, err = reg.Authenticate(signResp, *pa.challenges[i], 0)
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("authenticate error: matching registration not found")
}

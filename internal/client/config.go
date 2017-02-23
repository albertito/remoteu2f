package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/tstranex/u2f"
)

// Default configuration directory, relative to the user's home directory.
const DefaultConfigDir = ".remoteu2f"

// Default configuration file name.
const DefaultConfigFileName = "config"

// Client configuration structure.
// We read and write this to disk in toml format.
type Config struct {
	// Address of the GRPC server to use.
	Addr string

	// Client token used to request authorization to the server.
	Token string

	// U2F AppID to use. Usually "https://address/".
	AppID string

	// Backup codes, that allow emergency access.
	BackupCodes map[string]bool

	// Registrations.
	// Map of description -> marshalled registration.
	Registrations map[string][]byte
}

func ReadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c := &Config{}
	return c, json.Unmarshal(data, c)
}

func DefaultConfigFullPath(home string) string {
	if home == "" {
		home = os.Getenv("HOME")
	}
	return home + "/" + DefaultConfigDir + "/" + DefaultConfigFileName
}

func ReadDefaultConfig(home string) (*Config, error) {
	return ReadConfig(DefaultConfigFullPath(home))
}

func (c *Config) Write(path string) error {
	f, err := ioutil.TempFile("", "remoteu2f-config-")
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(c)
	if err != nil {
		os.Remove(f.Name())
		return err
	}

	// Format the json for increased readability.
	var out bytes.Buffer
	json.Indent(&out, b, "", "    ")
	out.WriteTo(f)

	return os.Rename(f.Name(), path)
}

func (c *Config) WriteToDefaultPath(home string) error {
	if home == "" {
		home = os.Getenv("HOME")
	}
	dir := home + "/" + DefaultConfigDir
	path := dir + "/" + DefaultConfigFileName
	os.MkdirAll(dir, 0700)
	err := c.Write(path)
	if err != nil {
		return fmt.Errorf("error writing to %q: %v", path, err)
	}
	return nil
}

func (c *Config) NewBackupCodes() error {
	codes := map[string]bool{}

	// 6 codes of 6 digits each.
	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			return err
		}
		sn := fmt.Sprintf("%06d", n)
		codes[sn] = true
	}

	c.BackupCodes = codes
	return nil
}

// RegistrationValues returns the registrations in the configuration file, as
// a slice of u2f.Registration structures (which is a friendly form for the
// client functions).
func (c *Config) RegistrationValues() []u2f.Registration {
	var rs []u2f.Registration
	for _, binr := range c.Registrations {
		r := u2f.Registration{}
		if err := r.UnmarshalBinary(binr); err != nil {
			// TODO - Should we account for this?
			// Backwards-incompatible changes could cause this.
			panic(err)
		}
		rs = append(rs, r)
	}
	return rs
}

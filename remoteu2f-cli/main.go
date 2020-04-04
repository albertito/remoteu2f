// remoteu2f command-line interface
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strings"

	"github.com/urfave/cli"

	"blitiri.com.ar/go/remoteu2f/internal/client"
)

var stdinScanner *bufio.Scanner

// readLine reads a line from os.Stdin and returns it.
// It exits the process on errors.
func readLine() string {
	if !stdinScanner.Scan() && stdinScanner.Err() != nil {
		fmt.Printf("Error reading from stdin: %v\n", stdinScanner.Err())
		os.Exit(1)
	}
	return strings.TrimSpace(stdinScanner.Text())
}

func main() {
	app := cli.NewApp()
	app.Name = "remoteu2f-cli"
	app.Usage = "remoteu2f command line tool"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "ca_file",
			Usage: "path to the CA file (default: use system's)",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:   "init",
			Usage:  "Create initial configuration (interactive)",
			Action: Init,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "override",
					Usage: "override the configuration if it exists",
				},
			},
		},
		{
			Name:   "register",
			Usage:  "Register a new security key",
			Action: Register,
		},
		{
			Name:   "auth",
			Usage:  "Perform a test authentication",
			Action: Authenticate,
		},
		{
			Name:   "new_backup_codes",
			Usage:  "Generate new backup codes, remove the old ones",
			Action: NewBackupCodes,
		},
		{
			Name:   "print_config",
			Usage:  "Print the config (useful for debugging)",
			Action: PrintConfig,
		},
		{
			Name:   "pam",
			Usage:  "Perform an authentication for PAM",
			Action: PAM,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "nullok",
					Usage: "return success if there is no configuration",
				},
			},
		},
	}

	// Initialize the stdin scanner so the subcommands can use it.
	stdinScanner = bufio.NewScanner(os.Stdin)

	app.RunAndExitOnError()
}

func fatalf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

func mustReadConfig() *client.Config {
	conf, err := client.ReadDefaultConfig("")
	if err != nil {
		fatalf("Error reading config: %v\n", err)
	}

	return conf
}

func mustWriteConfig(c *client.Config, homedir string) {
	err := c.WriteToDefaultPath(homedir)
	if err != nil {
		fatalf("Error writing config: %v\n", err)
	}
}

func mustGRPCClient(addr, token, caFile string) *client.RemoteU2FClient {
	c, err := client.GRPCClient(addr, token, caFile)
	if err != nil {
		fatalf("Error connecting with the server: %v\n", err)
	}

	return c
}

func mustUserInfo() (string, string) {
	user, err := user.Current()
	if err != nil {
		fatalf("error getting current user: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		fatalf("error getting hostname: %v", err)
	}

	return user.Username, hostname
}

func mustLookupHomeDir(username string) string {
	info, err := user.Lookup(username)
	if err != nil {
		fatalf("Could not find $HOME for user: %v\n", err)
	}

	return info.HomeDir
}

func printBackupCodes(conf *client.Config) {
	// Sort the codes so we get stable and more friendly output.
	var codes []string
	for c := range conf.BackupCodes {
		codes = append(codes, c)
	}
	sort.Strings(codes)

	for _, c := range codes {
		fmt.Printf("  %v\n", c)
	}
}

func printRegistrations(conf *client.Config) {
	// Sort the descriptions so we get stable and more friendly output.
	var ds []string
	for d := range conf.Registrations {
		ds = append(ds, d)
	}
	sort.Strings(ds)

	for _, d := range ds {
		fmt.Printf("  %q\n", d)
	}
}

func Init(ctx *cli.Context) {
	if !ctx.Bool("override") {
		// We don't want to accidentally override the config.
		_, err := client.ReadDefaultConfig("")
		if err == nil {
			fmt.Printf("Configuration already exists at %s\n",
				client.DefaultConfigFullPath(""))
			fmt.Printf("Use --override to continue anyway.\n")
			os.Exit(1)
		}
	}

	fmt.Printf("- GRPC server address to use? (e.g. 'mydomain.com:8801')\n")
	addr := readLine()
	fmt.Printf("- Authorization token? (given to you by the server admin)\n")
	token := readLine()

	fmt.Printf("- Contacting server...\n")
	c, err := client.GRPCClient(addr, token, ctx.GlobalString("ca_file"))
	if err != nil {
		fmt.Printf("Error connecting with the server: %v\n", err)
		fmt.Printf("Check the parameters above and try again.\n")
		os.Exit(1)
	}

	appID, err := c.GetAppID()
	if err != nil {
		fmt.Printf("RPC error: %v\n", err)
		fmt.Printf("Check the parameters above and try again.\n")
		os.Exit(1)
	}

	fmt.Printf("It worked!  AppID: %s\n", appID)

	conf := &client.Config{
		Addr:          addr,
		Token:         token,
		AppID:         appID,
		Registrations: map[string][]byte{},
	}

	err = conf.NewBackupCodes()
	if err != nil {
		fatalf("Error generating backup codes: %v\n", err)
	}

	mustWriteConfig(conf, "")
	fmt.Printf("Config written to %s\n", client.DefaultConfigFullPath(""))

	fmt.Printf("\n")
	fmt.Printf("Please write down your backup codes:\n")
	printBackupCodes(conf)

	fmt.Printf("\n")
	fmt.Printf("All done!\n")
	fmt.Printf("To register a security key, run:  remoteu2f-cli register\n")
}

func PrintConfig(ctx *cli.Context) {
	conf := mustReadConfig()
	fmt.Printf("GRPC address:   %s\n", conf.Addr)
	fmt.Printf("Client token:   %s\n", conf.Token)
	fmt.Printf("Application ID: %s\n", conf.AppID)

	fmt.Printf("Registered keys:\n")
	printRegistrations(conf)

	fmt.Printf("Backup codes:\n")
	printBackupCodes(conf)
}

func Register(ctx *cli.Context) {
	conf := mustReadConfig()
	c := mustGRPCClient(conf.Addr, conf.Token, ctx.GlobalString("ca_file"))

	user, hostname := mustUserInfo()
	msg := fmt.Sprintf("%s@%s", user, hostname)

	pr, err := c.PrepareRegister(msg, conf.AppID, conf.RegistrationValues())
	if err != nil {
		fatalf("Error preparing registration: %v\n", err)
	}
	fmt.Printf("Go to:  %s\n", pr.Key.Url)

	reg, err := c.CompleteRegister(pr)
	if err != nil {
		fatalf("Error completing registration: %v\n", err)
	}

	fmt.Printf("Description for this security key:\n")
	desc := readLine()

	if conf.Registrations == nil {
		conf.Registrations = map[string][]byte{}
	}
	conf.Registrations[desc] = reg

	mustWriteConfig(conf, "")
	fmt.Println("Success, registration written to config")
}

func Authenticate(ctx *cli.Context) {
	conf := mustReadConfig()
	c := mustGRPCClient(conf.Addr, conf.Token, ctx.GlobalString("ca_file"))

	user, hostname := mustUserInfo()
	msg := fmt.Sprintf("%s@%s", user, hostname)

	if len(conf.Registrations) == 0 {
		fmt.Printf("Error: no registrations found\n")
		fatalf("To register a security key, run:  remoteu2f-cli register\n")
	}

	pa, err := c.PrepareAuthentication(
		msg, conf.AppID, conf.RegistrationValues())
	if err != nil {
		fatalf("Error preparing authentication: %v\n", err)
	}
	fmt.Printf("Go to:  %s\n", pa.Key.Url)

	err = c.CompleteAuthentication(pa)
	if err != nil {
		fatalf("Error completing authentication: %v\n", err)
	}

	fmt.Println("Authentication succeeded")
}

func NewBackupCodes(ctx *cli.Context) {
	conf := mustReadConfig()
	err := conf.NewBackupCodes()
	if err != nil {
		fatalf("Error generating new backup codes: %v\n", err)
	}

	mustWriteConfig(conf, "")

	fmt.Printf("New backup codes:\n")
	for s, _ := range conf.BackupCodes {
		fmt.Printf("  %v\n", s)
	}
}

func PAM(ctx *cli.Context) {
	// We need to find the user's home first.
	username := os.Getenv("PAM_USER")
	homedir := mustLookupHomeDir(username)

	nullok := ctx.Bool("nullok")
	conf, err := client.ReadDefaultConfig(homedir)
	if err != nil {
		if nullok {
			os.Exit(0)
		} else {
			fatalf("Error reading config: %v\n", err)
		}
	}

	if len(conf.Registrations) == 0 {
		if nullok {
			os.Exit(0)
		} else {
			fatalf("Error: no registrations found\n")
		}
	}

	c := mustGRPCClient(conf.Addr, conf.Token, ctx.GlobalString("ca_file"))

	hostname, err := os.Hostname()
	if err != nil {
		fatalf("Error getting hostname: %v", err)
	}
	msg := fmt.Sprintf("%s@%s", username, hostname)

	pa, err := c.PrepareAuthentication(
		msg, conf.AppID, conf.RegistrationValues())
	if err != nil {
		fatalf("Error preparing authentication: %v\n", err)
	}

	fmt.Printf("Authenticate here and press enter:  %s\n", pa.Key.Url)

	// Closing stdout makes pam_prompt_exec send the prompt over.
	os.Stdout.Close()

	// Read input, and check if it's a backup code.
	// Never take a backup code of less than 6 characters, just in case some
	// data handling error makes them appear in conf.BackupCodes.
	input := readLine()
	if _, ok := conf.BackupCodes[input]; len(input) >= 6 && ok {
		delete(conf.BackupCodes, input)
		mustWriteConfig(conf, homedir)
		os.Exit(0)
	}

	err = c.CompleteAuthentication(pa)
	if err != nil {
		fatalf("Error completing authentication: %v\n", err)
	}

	os.Exit(0)
}

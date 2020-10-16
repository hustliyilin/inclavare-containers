package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/inclavare-containers/rune/libenclave"
	// "github.com/inclavare-containers/rune/libenclave/attestation/sgx"
	_ "github.com/inclavare-containers/rune/libenclave/attestation/sgx/ias"
	// "github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

const (
	envSeparator = "="
)

var attestCommand = cli.Command{
	Name:  "attest",
	Usage: "attest gets the remote or local report to the corresponding enclave container",
	ArgsUsage: `<container-id> [command options]
Where "<container-id>" is the name for the instance of the container`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "isRA",
			Usage: "specify whether to get the remote or local report",
		},
		cli.BoolFlag{
			Name:  "product",
			Usage: "specify whether using production attestation service",
		},
		cli.StringFlag{
			Name:  "spid",
			Usage: "specify SPID",
		},
		cli.StringFlag{
			Name:  "subscription-key, -key",
			Usage: "specify the subscription key",
		},
		cli.BoolFlag{
			Name:  "linkable",
			Usage: "specify the EPID signatures policy type",
		},
		cli.StringFlag{
			Name:  "reportFile",
			Usage: "path to the output report file(in the ${bundle}/rootfs) containing the corresponding REPORT(currently only using to save the local report)",
		},
	},
	Action: func(context *cli.Context) error {
		if err := revisePidFile(context); err != nil {
			return err
		}
		status, err := attestProcess(context)
		if err == nil {
			os.Exit(status)
		}
		return fmt.Errorf("attest failed: %v", err)
	},
	SkipArgReorder: true,
}

func attestProcess(context *cli.Context) (int, error) {
	container, err := getContainer(context)
	if err != nil {
		return -1, err
	}

	root, err := getContainerRootDir(context)
	agentSocket := filepath.Join(root, "agent.sock")
	fmt.Printf("agentSocket = %v\n", agentSocket)
	if err != nil {
		return -1, err
	}

	status, err := container.Status()
	if err != nil {
		return -1, err
	}
	if status == libenclave.Stopped {
		return -1, fmt.Errorf("cannot attest a container that has stopped")
	}

	state, err := container.State()
	if err != nil {
		return -1, err
	}
	bundle := utils.SearchLabels(state.Config.Labels, "bundle")
	_, err = getAttestProcess(context, bundle)
	if err != nil {
		return -1, err
	}

	return 1, nil
}

func getAttestProcess(context *cli.Context, bundle string) (*specs.Process, error) {
	// process via cli flags
	if err := os.Chdir(bundle); err != nil {
		return nil, err
	}
	spec, err := loadSpec(specConfig)
	if err != nil {
		return nil, err
	}
	p := spec.Process
	p.Args = context.Args()[1:]
	// override the cwd, if passed
	if context.String("cwd") != "" {
		p.Cwd = context.String("cwd")
	}
	if ap := context.String("apparmor"); ap != "" {
		p.ApparmorProfile = ap
	}
	if l := context.String("process-label"); l != "" {
		p.SelinuxLabel = l
	}
	if caps := context.StringSlice("cap"); len(caps) > 0 {
		for _, c := range caps {
			p.Capabilities.Bounding = append(p.Capabilities.Bounding, c)
			p.Capabilities.Inheritable = append(p.Capabilities.Inheritable, c)
			p.Capabilities.Effective = append(p.Capabilities.Effective, c)
			p.Capabilities.Permitted = append(p.Capabilities.Permitted, c)
			p.Capabilities.Ambient = append(p.Capabilities.Ambient, c)
		}
	}
	// append the passed env variables
	/* isRemoteAttestation := "false"
	if context.Bool("isRA") {
		isRemoteAttestation = "true"
	}
	p.Env = append(p.Env, "IsRemoteAttestation"+envSeparator+isRemoteAttestation)

	p.Env = append(p.Env, "SPID"+envSeparator+context.String("spid"))
	p.Env = append(p.Env, "SUBSCRIPTION_KEY"+envSeparator+context.String("subscription-key"))
	p.Env = append(p.Env, "REPORT_FILE"+envSeparator+context.String("reportFile"))

	isProductEnclave := strconv.Itoa(int(sgx.DebugEnclave))
	if context.Bool("product") {
		isProductEnclave = strconv.Itoa(int(sgx.ProductEnclave))
	}
	p.Env = append(p.Env, "PRODUCT"+envSeparator+isProductEnclave)

	quoteType := strconv.Itoa(int(intelsgx.QuoteSignatureTypeUnlinkable))
	if context.Bool("linkable") {
		quoteType = strconv.Itoa(int(intelsgx.QuoteSignatureTypeLinkable))
	}
	p.Env = append(p.Env, "QUOTE_TYPE"+envSeparator+quoteType) */

	var AttestCommand string = "true"
	p.Env = append(p.Env, "AttestCommand"+envSeparator+AttestCommand)

	// set the tty
	p.Terminal = false
	if context.IsSet("tty") {
		p.Terminal = context.Bool("tty")
	}
	if context.IsSet("no-new-privs") {
		p.NoNewPrivileges = context.Bool("no-new-privs")
	}
	// override the user, if passed
	if context.String("user") != "" {
		u := strings.SplitN(context.String("user"), ":", 2)
		if len(u) > 1 {
			gid, err := strconv.Atoi(u[1])
			if err != nil {
				return nil, fmt.Errorf("parsing %s as int for gid failed: %v", u[1], err)
			}
			p.User.GID = uint32(gid)
		}
		uid, err := strconv.Atoi(u[0])
		if err != nil {
			return nil, fmt.Errorf("parsing %s as int for uid failed: %v", u[0], err)
		}
		p.User.UID = uint32(uid)
	}
	for _, gid := range context.Int64Slice("additional-gids") {
		if gid < 0 {
			return nil, fmt.Errorf("additional-gids must be a positive number %d", gid)
		}
		p.User.AdditionalGids = append(p.User.AdditionalGids, uint32(gid))
	}
	return p, validateAttestProcessSpec(p)
}

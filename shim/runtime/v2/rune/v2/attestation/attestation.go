package attestation

import (
	"context"
	"fmt"
	"path"
	// _ "github.com/opencontainers/runc/libenclave/attestation/sgx/ias"
	"github.com/alibaba/inclavare-containers/shim/runtime/config"
	"github.com/alibaba/inclavare-containers/shim/runtime/v2/rune/constants"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"os/exec"
	"strings"
)

func GetRaParameters(bundlePath string) (raParameters map[string]string, err error) {
	configPath := path.Join(bundlePath, "config.json")
	p := make(map[string]string)

	var spec *specs.Spec
	spec, err = config.LoadSpec(configPath)
	if err != nil {
		return nil, fmt.Errorf("Load Spec:%s error:%s", configPath, err)
	}

	v, ok := config.GetEnv(spec, constants.EnvKeyRaType)
	if !ok {
		return nil, fmt.Errorf("Get Env:%s error:%s", constants.EnvKeyRaType, err)
	} else if v == "" {
		logrus.Infof("remote attestation parameters aren't set")
		return nil, nil
	}
	p[constants.EnvKeyRaType] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyIsProductEnclave)
	if !ok {
		return nil, fmt.Errorf("Get Env:%s error:%s", constants.EnvKeyIsProductEnclave, err)
	}
	p[constants.EnvKeyIsProductEnclave] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyRaEpidSpid)
	if !ok {
		return nil, fmt.Errorf("Get Env:%s error:%s", constants.EnvKeyRaEpidSpid, err)
	}
	p[constants.EnvKeyRaEpidSpid] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyRaEpidSubKey)
	if !ok {
		return nil, fmt.Errorf("Get Env:%s error:%s", constants.EnvKeyRaEpidSubKey, err)
	}
	p[constants.EnvKeyRaEpidSubKey] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyRaEpidIsLinkable)
	if !ok {
		return nil, fmt.Errorf("Get Env:%s error:%s", constants.EnvKeyRaEpidIsLinkable, err)
	}
	p[constants.EnvKeyRaEpidIsLinkable] = v

	return p, nil
}

func Attest(ctx context.Context, raParameters map[string]string, containerId string, root string) ([]byte, error) {
	if raParameters == nil {
		return nil, nil
	}

	if !strings.EqualFold(raParameters[constants.EnvKeyRaType], "true") {
		return nil, fmt.Errorf("Unsupported ra type:%s!\n", raParameters[constants.EnvKeyRaType])
	}

	/* spid and subscriptionKey is checked in
	 * package github.com/opencontainers/runc/libenclave/attestation/sgx/ias.
	 * so we only need to check containerId, product and linkable here.
	 */
	if containerId == "" {
		return nil, fmt.Errorf("Invalid container ID!\n")
	}

	if root == "" {
		return nil, fmt.Errorf("Invalid rune global options --root")
	}

	var args []string
	args = append(args, "--root", root, "attest",
		"--spid", raParameters[constants.EnvKeyRaEpidSpid],
		"--subscription-key", raParameters[constants.EnvKeyRaEpidSubKey])
	if strings.EqualFold(raParameters[constants.EnvKeyIsProductEnclave], "true") {
		args = append(args, "--product")
	}
	if strings.EqualFold(raParameters[constants.EnvKeyRaEpidIsLinkable], "true") {
		args = append(args, "--linkable")
	}
	cmd := exec.CommandContext(ctx, "rune", append(args, containerId)...)

	logrus.Infof("attestCmd = %v, raParameters = %v", cmd, raParameters)
	logrus.Infof("Begin remote attestation")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("remote attestation command failed with error: %s", err)
	}
	logrus.Infof("End remote attestation")

	return output, nil
}

func Attestation_main() {
	for true {
		// if opts != nil {
		// start remote attestation
		/* 	if opts.BinaryName == constants.RuneOCIRuntime {
				logrus.Infof("Attestation Start")
				raParameters, err := attestation.GetRaParameters(r.Bundle)
				if err != nil {
					return nil, err
				}

				ns, err := namespaces.NamespaceRequired(ctx)
				if err != nil {
					return nil, err
				}

				var runeRootGlobalOption string = process.RuncRoot
				if opts.Root != "" {
					runeRootGlobalOption = opts.Root
				}
				runeRootGlobalOption = filepath.Join(runeRootGlobalOption, ns)
				iasReport, err := attestation.Attest(ctx, raParameters, r.ID, runeRootGlobalOption)
				if err != nil {
					return nil, err
				}

				logrus.Infof("Attestation End: iasReport = %v", iasReport)
			}
		} */
	}
}

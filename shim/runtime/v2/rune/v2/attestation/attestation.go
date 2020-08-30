package attestation

import (
	// "bytes"
	"context"
	// "encoding/binary"
	"fmt"
	"path"
	"path/filepath"
	"github.com/alibaba/inclavare-containers/shim/runtime/config"
	"github.com/alibaba/inclavare-containers/shim/runtime/v2/rune/constants"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	_ "github.com/opencontainers/runc/libenclave/proto"
	// "io"
	"net"
	"strings"
)

const (
	agentSocket = "agent.sock"
)

const (
	QuoteSignatureTypeUnlinkable = iota
	QuoteSignatureTypeLinkable
	InvalidQuoteSignatureType
)

const (
	InvalidEnclaveType = iota
	DebugEnclave
	ProductEnclave
)

/* func protoBufWrite(conn io.Writer, marshaled interface{}) (err error) {
	var data []byte
	switch marshaled := marshaled.(type) {
	case *pb.AgentServiceRequest:
		data, err = proto.Marshal(marshaled)
	case *pb.AgentServiceResponse:
		data, err = proto.Marshal(marshaled)
	default:
		return fmt.Errorf("invalid type of marshaled data")
	}
	if err != nil {
		return err
	}

	sz := uint32(len(data))
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, &sz)
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
} */

/* func protoBufRead(conn io.Reader, unmarshaled interface{}) error {
        var sz uint32
        data := make([]byte, unsafe.Sizeof(sz))
        _, err := conn.Read(data)
        if err != nil {
                return err
        }
        buf := bytes.NewBuffer(data)
        sz = uint32(len(data))
        if err := binary.Read(buf, binary.LittleEndian, &sz); err != nil {
                return err
        }

        data = make([]byte, sz)
        if _, err := conn.Read(data); err != nil {
                return err
        }

        switch unmarshaled := unmarshaled.(type) {
        case *pb.AgentServiceRequest:
                err = proto.Unmarshal(data, unmarshaled)
        case *pb.AgentServiceResponse:
                err = proto.Unmarshal(data, unmarshaled)
        default:
                return fmt.Errorf("invalid type of unmarshaled data")
        }
        return err
} */

func dialAgentSocket(root string, containerId string) (*net.UnixConn, error) {
	agentSock := filepath.Join(root, containerId, agentSocket)
	addr, err := net.ResolveUnixAddr("unix", agentSock)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

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

	_, err := dialAgentSocket(root, containerId)
	// conn, err := dialAgentSocket()
	if err != nil {
		return nil, err
	}

	isProductEnclave := DebugEnclave
	if strings.EqualFold(raParameters[constants.EnvKeyIsProductEnclave], "true") {
		isProductEnclave = ProductEnclave
	}

	raEpidQuoteType := QuoteSignatureTypeUnlinkable
	if strings.EqualFold(raParameters[constants.EnvKeyRaEpidIsLinkable], "true") {
		raEpidQuoteType = QuoteSignatureTypeLinkable
	}

	logrus.Infof("isProductEnclave = %v, raEpidQuoteType = %v", isProductEnclave, raEpidQuoteType)

	/* req := &pb.AgentServiceRequest{}
	req.Attest = &pb.AgentServiceRequest_Attest{
		Spid:            raParameters[constants.EnvKeyRaEpidSpid],
		SubscriptionKey: raParameters[constants.EnvKeyRaEpidSubKey],
		Product:         (uint32)(isProductEnclave),
		QuoteType:       (uint32)(raEpidQuoteType),
	}

	if err = protoBufWrite(conn, req); err != nil {
		return nil, err
	}*/

	logrus.Infof("Begin remote attestation")

	/* resp := &pb.AgentServiceResponse{}
        if err = protoBufRead(conn, resp); err != nil {
                return 1, err
        } */

	logrus.Infof("End remote attestation")

	/* if resp.Attest.Error == "" {
                err = nil
        } else {
                err = fmt.Errorf(resp.Attest.Error)
        }

        iasReport := make(map[string]string)

        iasReport["StatusCode"] = resp.Attest.StatusCode
        iasReport["Request-ID"] = resp.Attest.RequestID
        iasReport["X-Iasreport-Signature"] = resp.Attest.XIasreportSignature
        iasReport["X-Iasreport-Signing-Certificate"] = resp.Attest.XIasreportSigningCertificate
        iasReport["ContentLength"] = resp.Attest.ContentLength
        iasReport["Content-Type"] = resp.Attest.ContentType
        iasReport["Body"] = iasReport["Body"]

        logrus.Infof("iasReport = %v", iasReport) */

	return nil, nil
}

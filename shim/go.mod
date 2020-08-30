module github.com/alibaba/inclavare-containers/shim

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/containerd/cgroups v0.0.0-20190919134610-bf292b21730f
	github.com/containerd/containerd v1.3.3
	github.com/containerd/fifo v0.0.0-20191213151349-ff969a566b00 // indirect
	github.com/containerd/go-runc v0.0.0-20200220073739-7016d3ce2328
	github.com/containerd/ttrpc v1.0.0 // indirect
	github.com/containerd/typeurl v1.0.0
	github.com/docker/distribution v0.0.0-00010101000000-000000000000 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/gin-gonic/gin v1.6.3
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/gogo/protobuf v1.3.1
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/imdario/mergo v0.3.9 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.1.1
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	go.etcd.io/bbolt v1.3.4 // indirect
	golang.org/x/sys v0.0.0-20200331124033-c3d80250170d
	gopkg.in/yaml.v2 v2.3.0 // indirect
	k8s.io/apimachinery v0.18.2

)

replace (
	github.com/docker/distribution => github.com/docker/distribution v2.7.1-0.20190205005809-0d3efadf0154+incompatible
	// github.com/opencontainers/runc => github.com/alibaba/inclavare-containers/rune v0.0.0-20200527123028-5b951e6d3bb0
	// github.com/opencontainers/runc => github.com/alibaba/inclavare-containers/rune v0.0.0-20200828143903-196cf5ad4180
	// github.com/opencontainers/runc => github.com/alibaba/inclavare-containers/rune v0.0.0-20200824174404-0364b2ac42dc
	// github.com/opencontainers/runc => github.com/hustliyilin/inclavare-containers/rune v0.0.0-20200512065524-c9751df2e241
	// github.com/opencontainers/runc => github.com/hustliyilin/inclavare-containers/rune v0.0.0-20200830151934-729383d9725a
	github.com/opencontainers/runc => github.com/hustliyilin/inclavare-containers/rune v0.0.0-20200830160541-3154e2e49306
)

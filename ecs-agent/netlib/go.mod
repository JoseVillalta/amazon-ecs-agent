module github.com/aws/amazon-ecs-agent/ecs-agent/netlib

go 1.24.0

toolchain go1.24.2

require (
	github.com/Microsoft/hcsshim v0.12.0
	github.com/aws/amazon-ecs-agent/ecs-agent v0.0.0
	github.com/aws/aws-sdk-go-v2 v1.41.4
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.20
	github.com/aws/aws-sdk-go-v2/service/ecs v0.0.0-00010101000000-000000000000
	github.com/containernetworking/cni v1.1.2
	github.com/containernetworking/plugins v1.4.1
	github.com/golang/mock v1.6.0
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.11.1
	github.com/vishvananda/netlink v1.2.1-beta.2
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/aws/aws-sdk-go v1.55.7 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	github.com/containerd/cgroups/v3 v3.0.2 // indirect
	github.com/containerd/errdefs v0.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/aws/amazon-ecs-agent/ecs-agent => ../
	github.com/aws/aws-sdk-go-v2/service/ecs => ../../aws-sdk-go-v2/service/ecs
)

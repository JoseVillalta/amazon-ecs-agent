// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ec2

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

const (
	// There are three categories of instance metadata.
	// 1. Instance metadata properties. Accessed through GetMetadata(path).
	// 2. Dynamic data. Accessed through GetDynamicData(path).
	// 3. User data. Access through GetUserData().
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html

	// Paths for the instance metadata properties.
	SecurityCredentialsResource      = "iam/security-credentials/"
	MacResource                      = "mac"
	AllMacResource                   = "network/interfaces/macs"
	VPCIDResourceFormat              = "network/interfaces/macs/%s/vpc-id"
	SubnetIDResourceFormat           = "network/interfaces/macs/%s/subnet-id"
	SpotInstanceActionResource       = "spot/instance-action"
	InstanceIDResource               = "instance-id"
	RegionResource                   = "placement/region"
	AvailabilityZoneID               = "placement/availability-zone-id"
	PrivateIPv4Resource              = "local-ipv4"
	PublicIPv4Resource               = "public-ipv4"
	IPv6Resource                     = "ipv6"
	OutpostARN                       = "outpost-arn"
	PrimaryIPV4VPCCIDRResourceFormat = "network/interfaces/macs/%s/vpc-ipv4-cidr-block"
	TargetLifecycleState             = "autoscaling/target-lifecycle-state"

	// Paths for dynamic data categories.
	InstanceIdentityDocumentResource          = "instance-identity/document"
	InstanceIdentityDocumentSignatureResource = "instance-identity/signature"
)

// RoleCredentials contains the information associated with an IAM role
type RoleCredentials struct {
	Code            string    `json:"Code"`
	LastUpdated     time.Time `json:"LastUpdated"`
	Type            string    `json:"Type"`
	AccessKeyId     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

// EC2MetadataClient is the client used to get metadata from instance metadata service
type EC2MetadataClient interface {
	DefaultCredentials() (*RoleCredentials, error)
	GetMetadata(string) (string, error)
	GetDynamicData(string) (string, error)
	InstanceIdentityDocument() (imds.InstanceIdentityDocument, error)
	VPCID(mac string) (string, error)
	SubnetID(mac string) (string, error)
	PrimaryENIMAC() (string, error)
	AllENIMacs() (string, error)
	InstanceID() (string, error)
	GetUserData() (string, error)
	Region() (string, error)
	AvailabilityZoneID() (string, error)
	PrivateIPv4Address() (string, error)
	PublicIPv4Address() (string, error)
	IPv6Address() (string, error)
	SpotInstanceAction() (string, error)
	OutpostARN() (string, error)
	TargetLifecycleState() (string, error)
}

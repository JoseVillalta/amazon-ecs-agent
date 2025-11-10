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

package ecscni

import (
	"fmt"
)

// PortMapEntry corresponds to a single entry in the port_mappings argument
type PortMapEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

// PortMapConfig defines the configuration for portmapper plugin
type PortMapConfig struct {
	CNIConfig

	// Generic config
	Backend       *string   `json:"backend,omitempty"`
	SNAT          *bool     `json:"snat,omitempty"`
	ConditionsV4  *[]string `json:"conditionsV4,omitempty"`
	ConditionsV6  *[]string `json:"conditionsV6,omitempty"`
	MasqAll       bool      `json:"masqAll,omitempty"`
	MarkMasqBit   *int      `json:"markMasqBit,omitempty"`

	// Runtime configuration populated by the agent
	RuntimeConfig struct {
		PortMaps []PortMapEntry `json:"portMappings,omitempty"`
	} `json:"runtimeConfig,omitempty"`

	// iptables-backend-specific config
	ExternalSetMarkChain *string `json:"externalSetMarkChain,omitempty"`

	// DeviceName is the name of the interface inside the namespace
	DeviceName string `json:"-"`

	// PrevResult will be populated at runtime from the previous plugin
	PrevResult map[string]interface{} `json:"prevResult,omitempty"`
}

func (pmc *PortMapConfig) String() string {
	return fmt.Sprintf("%s, portMaps: %d", pmc.CNIConfig.String(), len(pmc.RuntimeConfig.PortMaps))
}

// InterfaceName returns the interface name to be used inside the namespace
func (pmc *PortMapConfig) InterfaceName() string {
	if pmc.DeviceName == "" {
		return DefaultInterfaceName
	}
	return pmc.DeviceName
}

func (pmc *PortMapConfig) NSPath() string {
	return pmc.NetNSPath
}

func (pmc *PortMapConfig) CNIVersion() string {
	return pmc.CNISpecVersion
}

func (pmc *PortMapConfig) PluginName() string {
	return pmc.CNIPluginName
}
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

//go:build unit
// +build unit

package ecscni

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPortMapEntry(t *testing.T) {
	entry := PortMapEntry{
		HostPort:      8080,
		ContainerPort: 80,
		Protocol:      "tcp",
		HostIP:        "0.0.0.0",
	}

	// Test JSON marshaling
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled PortMapEntry
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, entry, unmarshaled)
}

func TestPortMapEntryWithoutHostIP(t *testing.T) {
	entry := PortMapEntry{
		HostPort:      8080,
		ContainerPort: 80,
		Protocol:      "tcp",
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var unmarshaled PortMapEntry
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, entry, unmarshaled)
}

func TestPortMapConfig_String(t *testing.T) {
	config := &PortMapConfig{
		CNIConfig: CNIConfig{
			NetNSPath:      "/proc/123/ns/net",
			CNISpecVersion: "0.3.1",
			CNIPluginName:  "portmap",
		},
		RuntimeConfig: struct {
			PortMaps []PortMapEntry `json:"portMappings,omitempty"`
		}{
			PortMaps: []PortMapEntry{
				{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
				{HostPort: 8443, ContainerPort: 443, Protocol: "tcp"},
			},
		},
	}

	result := config.String()
	assert.Contains(t, result, "portMaps: 2")
	assert.Contains(t, result, "/proc/123/ns/net")
	assert.Contains(t, result, "0.3.1")
	assert.Contains(t, result, "portmap")
}

func TestPortMapConfig_InterfaceName(t *testing.T) {
	tests := []struct {
		name       string
		deviceName string
		expected   string
	}{
		{
			name:       "default interface name",
			deviceName: "",
			expected:   DefaultInterfaceName,
		},
		{
			name:       "custom interface name",
			deviceName: "eth1",
			expected:   "eth1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PortMapConfig{
				DeviceName: tt.deviceName,
			}
			assert.Equal(t, tt.expected, config.InterfaceName())
		})
	}
}

func TestPortMapConfig_NSPath(t *testing.T) {
	nsPath := "/proc/123/ns/net"
	config := &PortMapConfig{
		CNIConfig: CNIConfig{
			NetNSPath: nsPath,
		},
	}
	assert.Equal(t, nsPath, config.NSPath())
}

func TestPortMapConfig_CNIVersion(t *testing.T) {
	version := "0.3.1"
	config := &PortMapConfig{
		CNIConfig: CNIConfig{
			CNISpecVersion: version,
		},
	}
	assert.Equal(t, version, config.CNIVersion())
}

func TestPortMapConfig_PluginName(t *testing.T) {
	pluginName := "portmap"
	config := &PortMapConfig{
		CNIConfig: CNIConfig{
			CNIPluginName: pluginName,
		},
	}
	assert.Equal(t, pluginName, config.PluginName())
}

func TestPortMapConfig_JSONMarshaling(t *testing.T) {
	snatTrue := true
	markBit := 13
	backend := "iptables"
	conditions := []string{"-d", "192.168.1.0/24"}
	externalChain := "CUSTOM-MARK"

	config := &PortMapConfig{
		CNIConfig: CNIConfig{
			NetNSPath:      "/proc/123/ns/net",
			CNISpecVersion: "0.3.1",
			CNIPluginName:  "portmap",
		},
		Backend:      &backend,
		SNAT:         &snatTrue,
		ConditionsV4: &conditions,
		MasqAll:      true,
		MarkMasqBit:  &markBit,
		RuntimeConfig: struct {
			PortMaps []PortMapEntry `json:"portMappings,omitempty"`
		}{
			PortMaps: []PortMapEntry{
				{HostPort: 8080, ContainerPort: 80, Protocol: "tcp", HostIP: "0.0.0.0"},
			},
		},
		ExternalSetMarkChain: &externalChain,
		DeviceName:           "eth0",
		PrevResult: map[string]interface{}{
			"cniVersion": "0.3.1",
			"ips": []interface{}{
				map[string]interface{}{
					"version":   "4",
					"address":   "10.0.0.5/32",
					"interface": float64(0),
				},
			},
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(config)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled PortMapConfig
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify key fields
	assert.Equal(t, config.CNISpecVersion, unmarshaled.CNISpecVersion)
	assert.Equal(t, config.CNIPluginName, unmarshaled.CNIPluginName)
	assert.Equal(t, *config.Backend, *unmarshaled.Backend)
	assert.Equal(t, *config.SNAT, *unmarshaled.SNAT)
	assert.Equal(t, *config.ConditionsV4, *unmarshaled.ConditionsV4)
	assert.Equal(t, config.MasqAll, unmarshaled.MasqAll)
	assert.Equal(t, *config.MarkMasqBit, *unmarshaled.MarkMasqBit)
	assert.Equal(t, len(config.RuntimeConfig.PortMaps), len(unmarshaled.RuntimeConfig.PortMaps))
	assert.Equal(t, *config.ExternalSetMarkChain, *unmarshaled.ExternalSetMarkChain)
	assert.Equal(t, config.PrevResult, unmarshaled.PrevResult)
}

func TestPortMapConfig_MinimalConfig(t *testing.T) {
	config := &PortMapConfig{
		CNIConfig: CNIConfig{
			NetNSPath:      "/proc/123/ns/net",
			CNISpecVersion: "0.3.1",
			CNIPluginName:  "portmap",
		},
	}

	// Test JSON marshaling with minimal config
	data, err := json.Marshal(config)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled PortMapConfig
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, config.CNISpecVersion, unmarshaled.CNISpecVersion)
	assert.Equal(t, config.CNIPluginName, unmarshaled.CNIPluginName)
	assert.Nil(t, unmarshaled.Backend)
	assert.Nil(t, unmarshaled.SNAT)
	assert.Nil(t, unmarshaled.ConditionsV4)
	assert.False(t, unmarshaled.MasqAll)
	assert.Nil(t, unmarshaled.MarkMasqBit)
	assert.Empty(t, unmarshaled.RuntimeConfig.PortMaps)
}

func TestPortMapConfig_ImplementsPluginConfig(t *testing.T) {
	config := &PortMapConfig{
		CNIConfig: CNIConfig{
			NetNSPath:      "/proc/123/ns/net",
			CNISpecVersion: "0.3.1",
			CNIPluginName:  "portmap",
		},
		DeviceName: "eth1",
	}

	// Verify it implements PluginConfig interface
	var _ PluginConfig = config

	// Test interface methods
	assert.Equal(t, "/proc/123/ns/net", config.NSPath())
	assert.Equal(t, "0.3.1", config.CNIVersion())
	assert.Equal(t, "portmap", config.PluginName())
	assert.Equal(t, "eth1", config.InterfaceName())
	assert.Equal(t, "container-id", config.ContainerID())
	assert.Equal(t, "network-name", config.NetworkName())
}
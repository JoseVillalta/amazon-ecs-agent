//go:build unit
// +build unit

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

package tasknetworkconfig

import (
	"encoding/json"
	"testing"

	"github.com/aws/amazon-ecs-agent/ecs-agent/netlib/model/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkNamespacePortMaps(t *testing.T) {
	portMaps := []PortMapEntry{
		{
			HostPort:      8080,
			ContainerPort: 80,
			Protocol:      "tcp",
		},
		{
			HostPort:      8443,
			ContainerPort: 443,
			Protocol:      "tcp",
			HostIP:        "0.0.0.0",
		},
	}

	ns := &NetworkNamespace{
		Name:         "test-namespace",
		Path:         "/var/run/netns/test",
		KnownState:   status.NetworkNone,
		DesiredState: status.NetworkReadyPull,
		PortMaps:     portMaps,
	}

	// Test that PortMaps field is properly set
	assert.Equal(t, portMaps, ns.PortMaps)
	assert.Len(t, ns.PortMaps, 2)

	// Test first port mapping
	assert.Equal(t, 8080, ns.PortMaps[0].HostPort)
	assert.Equal(t, 80, ns.PortMaps[0].ContainerPort)
	assert.Equal(t, "tcp", ns.PortMaps[0].Protocol)
	assert.Empty(t, ns.PortMaps[0].HostIP)

	// Test second port mapping
	assert.Equal(t, 8443, ns.PortMaps[1].HostPort)
	assert.Equal(t, 443, ns.PortMaps[1].ContainerPort)
	assert.Equal(t, "tcp", ns.PortMaps[1].Protocol)
	assert.Equal(t, "0.0.0.0", ns.PortMaps[1].HostIP)
}

func TestNetworkNamespacePortMapsEmpty(t *testing.T) {
	ns := &NetworkNamespace{
		Name:         "test-namespace",
		Path:         "/var/run/netns/test",
		KnownState:   status.NetworkNone,
		DesiredState: status.NetworkReadyPull,
		PortMaps:     []PortMapEntry{},
	}

	// Test that empty PortMaps field works correctly
	assert.Empty(t, ns.PortMaps)
	assert.Len(t, ns.PortMaps, 0)
}

func TestNetworkNamespacePortMapsNil(t *testing.T) {
	ns := &NetworkNamespace{
		Name:         "test-namespace",
		Path:         "/var/run/netns/test",
		KnownState:   status.NetworkNone,
		DesiredState: status.NetworkReadyPull,
		PortMaps:     nil,
	}

	// Test that nil PortMaps field works correctly
	assert.Nil(t, ns.PortMaps)
	assert.Len(t, ns.PortMaps, 0)
}

func TestNetworkNamespaceJSONSerialization(t *testing.T) {
	portMaps := []PortMapEntry{
		{
			HostPort:      8080,
			ContainerPort: 80,
			Protocol:      "tcp",
		},
	}

	ns := &NetworkNamespace{
		Name:         "test-namespace",
		Path:         "/var/run/netns/test",
		KnownState:   status.NetworkNone,
		DesiredState: status.NetworkReadyPull,
		PortMaps:     portMaps,
	}

	// Test JSON marshaling
	data, err := json.Marshal(ns)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled NetworkNamespace
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify PortMaps are preserved through serialization
	assert.Equal(t, ns.PortMaps, unmarshaled.PortMaps)
	assert.Len(t, unmarshaled.PortMaps, 1)
	assert.Equal(t, 8080, unmarshaled.PortMaps[0].HostPort)
	assert.Equal(t, 80, unmarshaled.PortMaps[0].ContainerPort)
	assert.Equal(t, "tcp", unmarshaled.PortMaps[0].Protocol)
}
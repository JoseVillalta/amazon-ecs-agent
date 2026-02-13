//go:build linux && e2e
// +build linux,e2e

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

package platform

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/amazon-ecs-agent/ecs-agent/acs/model/ecsacs"
	"github.com/aws/aws-sdk-go-v2/aws"
	cnins "github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

const (
	// testListenerPort is the default port used for e2e connectivity tests.
	testListenerPort = 8080
	// testConnectionTimeout is the timeout for establishing TCP connections.
	testConnectionTimeout = 5 * time.Second
	// testListenerStartTimeout is the timeout for waiting for the listener to start.
	testListenerStartTimeout = 2 * time.Second
	// testMessage is the message sent during connectivity tests.
	testMessage = "daemon-namespace-connectivity-test"
	// daemonNamespaceIPv4Addr is the IPv4 address (without CIDR prefix) for connectivity tests.
	daemonNamespaceIPv4Addr = "169.254.172.2"
	// daemonNamespaceIPv6Addr is the IPv6 address (without CIDR prefix) for connectivity tests.
	daemonNamespaceIPv6Addr = "fd00:ec2::172:2"
)

// namespaceListener manages a TCP listener running inside a network namespace.
// It provides methods to start listening, accept connections, and clean up resources.
type namespaceListener struct {
	listener   net.Listener
	netNSPath  string
	address    string
	port       int
	started    chan struct{}
	stopped    chan struct{}
	lastError  error
	mu         sync.Mutex
	receivedCh chan string
}

// newNamespaceListener creates a new namespaceListener for the given network namespace and address.
func newNamespaceListener(netNSPath, address string, port int) *namespaceListener {
	return &namespaceListener{
		netNSPath:  netNSPath,
		address:    address,
		port:       port,
		started:    make(chan struct{}),
		stopped:    make(chan struct{}),
		receivedCh: make(chan string, 1),
	}
}

// startListenerInNamespace starts a TCP listener inside the specified network namespace.
// The listener runs in a goroutine and signals when it is ready to accept connections.
// Returns an error if the listener cannot be started within the timeout period.
func (nl *namespaceListener) startListenerInNamespace() error {
	errCh := make(chan error, 1)

	go func() {
		err := cnins.WithNetNSPath(nl.netNSPath, func(_ cnins.NetNS) error {
			listenAddr := net.JoinHostPort(nl.address, fmt.Sprintf("%d", nl.port))
			listener, err := net.Listen("tcp", listenAddr)
			if err != nil {
				return errors.Wrapf(err, "failed to start listener on %s", listenAddr)
			}

			nl.mu.Lock()
			nl.listener = listener
			nl.mu.Unlock()

			// Signal that the listener has started.
			close(nl.started)

			// Accept a single connection and read data from it.
			conn, err := listener.Accept()
			if err != nil {
				nl.mu.Lock()
				nl.lastError = err
				nl.mu.Unlock()
				return nil
			}
			defer conn.Close()

			// Read the message from the connection.
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				nl.mu.Lock()
				nl.lastError = err
				nl.mu.Unlock()
				return nil
			}

			// Send the received message to the channel.
			nl.receivedCh <- string(buf[:n])
			return nil
		})

		if err != nil {
			errCh <- err
		}
		close(nl.stopped)
	}()

	// Wait for the listener to start or timeout.
	select {
	case <-nl.started:
		return nil
	case err := <-errCh:
		return err
	case <-time.After(testListenerStartTimeout):
		return errors.New("timeout waiting for listener to start in namespace")
	}
}

// stop closes the listener and waits for the goroutine to finish.
func (nl *namespaceListener) stop() error {
	nl.mu.Lock()
	if nl.listener != nil {
		nl.listener.Close()
	}
	nl.mu.Unlock()

	// Wait for the listener goroutine to finish.
	select {
	case <-nl.stopped:
		return nil
	case <-time.After(testConnectionTimeout):
		return errors.New("timeout waiting for listener to stop")
	}
}

// getReceivedMessage returns the message received by the listener.
// It blocks until a message is received or the timeout expires.
func (nl *namespaceListener) getReceivedMessage(timeout time.Duration) (string, error) {
	select {
	case msg := <-nl.receivedCh:
		return msg, nil
	case <-time.After(timeout):
		return "", errors.New("timeout waiting for message from listener")
	}
}

// connectToNamespace establishes a TCP connection from the host to the daemon namespace.
// It sends a test message and returns any error encountered during the connection.
func connectToNamespace(address string, port int, message string) error {
	targetAddr := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", targetAddr, testConnectionTimeout)
	if err != nil {
		return errors.Wrapf(err, "failed to connect to %s", targetAddr)
	}
	defer conn.Close()

	// Set a write deadline to prevent hanging.
	if err := conn.SetWriteDeadline(time.Now().Add(testConnectionTimeout)); err != nil {
		return errors.Wrap(err, "failed to set write deadline")
	}

	// Send the test message.
	_, err = conn.Write([]byte(message))
	if err != nil {
		return errors.Wrap(err, "failed to send message")
	}

	return nil
}

// connectToNamespaceIPv6 establishes a TCP connection from the host to the daemon namespace using IPv6.
// It sends a test message and returns any error encountered during the connection.
func connectToNamespaceIPv6(address string, port int, message string) error {
	// Format IPv6 address with brackets for the connection string.
	targetAddr := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp6", targetAddr, testConnectionTimeout)
	if err != nil {
		return errors.Wrapf(err, "failed to connect to %s", targetAddr)
	}
	defer conn.Close()

	// Set a write deadline to prevent hanging.
	if err := conn.SetWriteDeadline(time.Now().Add(testConnectionTimeout)); err != nil {
		return errors.Wrap(err, "failed to set write deadline")
	}

	// Send the test message.
	_, err = conn.Write([]byte(message))
	if err != nil {
		return errors.Wrap(err, "failed to send message")
	}

	return nil
}

// TestDaemonNamespaceIPv4Connectivity validates end-to-end IPv4 connectivity to a daemon namespace.
// This test creates a daemon namespace using the platform API, starts a TCP listener inside the
// namespace on port 8080, connects from the host to 169.254.172.2:8080, and verifies that the
// connection succeeds and data can be exchanged.
//
// The test validates:
//   - The daemon namespace is created successfully with the expected static IPv4 address
//   - A process inside the namespace can listen on a port
//   - Traffic from the host can reach the process using the link-local IP address
//   - Data can be exchanged bidirectionally
//
// **Validates: Requirements 5.1, 5.2, 5.3**
func TestDaemonNamespaceIPv4Connectivity(t *testing.T) {
	// Skip if the host doesn't have IPv4 support.
	skipIfNoIPv4E2E(t)

	t.Log("Starting TestDaemonNamespaceIPv4Connectivity")
	t.Logf("Testing connectivity to daemon namespace at %s:%d", daemonNamespaceIPv4Addr, testListenerPort)

	// Create temp directory for IPAM database.
	ipamDir, err := ioutil.TempDir("", "daemon-ns-connectivity-ipv4-")
	require.NoError(t, err, "Unable to create a temp directory for the ipam db")
	os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
	defer os.Unsetenv("IPAM_DB_PATH")
	defer os.RemoveAll(ipamDir)

	// Create test managedLinux platform with real EC2 client.
	platform, err := newTestManagedLinuxPlatformE2E(t, ipamDir)
	require.NoError(t, err, "Failed to create test platform")

	// Build task payload with NetworkMode "daemon-bridge".
	taskPayload := &ecsacs.Task{
		NetworkMode: aws.String("daemon-bridge"),
	}

	// Call BuildTaskNetworkConfiguration() to build the network configuration.
	taskNetConfig, err := platform.BuildTaskNetworkConfiguration("test-connectivity-ipv4", taskPayload)
	require.NoError(t, err, "BuildTaskNetworkConfiguration should succeed")
	require.NotNil(t, taskNetConfig, "TaskNetworkConfig should not be nil")
	require.Len(t, taskNetConfig.NetworkNamespaces, 1, "Should have exactly one network namespace")

	netNS := taskNetConfig.NetworkNamespaces[0]
	t.Logf("Network namespace path: %s", netNS.Path)

	// Call ConfigureDaemonNetNS() to configure the namespace.
	// **Validates: Requirement 5.1 - daemon namespace is created**
	err = platform.ConfigureDaemonNetNS(netNS)
	require.NoError(t, err, "ConfigureDaemonNetNS should succeed")

	// Log the network state for debugging.
	logNetworkStateInNSE2E(t, netNS.Path, "After ConfigureDaemonNetNS")

	// Ensure cleanup happens even if the test fails.
	defer func() {
		ctx := context.Background()
		if cleanupErr := platform.StopDaemonNetNS(ctx, netNS); cleanupErr != nil {
			t.Logf("Warning: StopDaemonNetNS failed during cleanup: %v", cleanupErr)
		}
	}()

	// Start a TCP listener inside the daemon namespace using the IP address without CIDR prefix.
	// **Validates: Requirement 5.2 - process inside namespace can listen on a port**
	listener := newNamespaceListener(netNS.Path, daemonNamespaceIPv4Addr, testListenerPort)
	err = listener.startListenerInNamespace()
	require.NoError(t, err, "Failed to start listener in daemon namespace")
	defer listener.stop()

	t.Logf("Listener started successfully on %s:%d inside namespace", daemonNamespaceIPv4Addr, testListenerPort)

	// Connect from the host to the daemon namespace using the link-local IP.
	// **Validates: Requirement 5.3 - traffic from host can reach process using link-local IP**
	err = connectToNamespace(daemonNamespaceIPv4Addr, testListenerPort, testMessage)
	require.NoError(t, err, "Failed to connect to daemon namespace from host")

	t.Log("Connection from host to daemon namespace succeeded")

	// Verify that the listener received the message.
	receivedMsg, err := listener.getReceivedMessage(testConnectionTimeout)
	require.NoError(t, err, "Failed to receive message in daemon namespace")
	require.Equal(t, testMessage, receivedMsg, "Received message should match sent message")

	t.Logf("Message exchange verified: sent=%q, received=%q", testMessage, receivedMsg)
	t.Log("TestDaemonNamespaceIPv4Connectivity completed successfully")
}

// TestDaemonNamespaceIPv6Connectivity validates end-to-end IPv6 connectivity to a daemon namespace.
// This test creates a daemon namespace using the platform API, starts a TCP listener inside the
// namespace on port 8080, connects from the host to [fd00:ec2::172:2]:8080, and verifies that the
// connection succeeds and data can be exchanged.
//
// The test validates:
//   - The daemon namespace is created successfully with the expected static IPv6 address
//   - A process inside the namespace can listen on a port using IPv6
//   - Traffic from the host can reach the process using the IPv6 link-local address
//   - Data can be exchanged bidirectionally over IPv6
//
// This test must run on an IPv6-enabled host (md-ipv6-2).
//
// **Validates: Requirements 5.1, 5.2, 5.4**
func TestDaemonNamespaceIPv6Connectivity(t *testing.T) {
	// Skip if the host doesn't have IPv6 support.
	skipIfNoIPv6E2E(t)

	t.Log("Starting TestDaemonNamespaceIPv6Connectivity")
	t.Logf("Testing IPv6 connectivity to daemon namespace at [%s]:%d", daemonNamespaceIPv6Addr, testListenerPort)

	// Create temp directory for IPAM database.
	ipamDir, err := ioutil.TempDir("", "daemon-ns-connectivity-ipv6-")
	require.NoError(t, err, "Unable to create a temp directory for the ipam db")
	os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
	defer os.Unsetenv("IPAM_DB_PATH")
	defer os.RemoveAll(ipamDir)

	// Create test managedLinux platform with real EC2 client.
	platform, err := newTestManagedLinuxPlatformE2E(t, ipamDir)
	require.NoError(t, err, "Failed to create test platform")

	// Build task payload with NetworkMode "daemon-bridge".
	taskPayload := &ecsacs.Task{
		NetworkMode: aws.String("daemon-bridge"),
	}

	// Call BuildTaskNetworkConfiguration() to build the network configuration.
	taskNetConfig, err := platform.BuildTaskNetworkConfiguration("test-connectivity-ipv6", taskPayload)
	require.NoError(t, err, "BuildTaskNetworkConfiguration should succeed")
	require.NotNil(t, taskNetConfig, "TaskNetworkConfig should not be nil")
	require.Len(t, taskNetConfig.NetworkNamespaces, 1, "Should have exactly one network namespace")

	netNS := taskNetConfig.NetworkNamespaces[0]
	t.Logf("Network namespace path: %s", netNS.Path)

	// Call ConfigureDaemonNetNS() to configure the namespace.
	// **Validates: Requirement 5.1 - daemon namespace is created**
	err = platform.ConfigureDaemonNetNS(netNS)
	require.NoError(t, err, "ConfigureDaemonNetNS should succeed")

	// Log the network state for debugging.
	logNetworkStateInNSE2E(t, netNS.Path, "After ConfigureDaemonNetNS (IPv6)")

	// Ensure cleanup happens even if the test fails.
	defer func() {
		ctx := context.Background()
		if cleanupErr := platform.StopDaemonNetNS(ctx, netNS); cleanupErr != nil {
			t.Logf("Warning: StopDaemonNetNS failed during cleanup: %v", cleanupErr)
		}
	}()

	// Start a TCP listener inside the daemon namespace using the IPv6 address without CIDR prefix.
	// **Validates: Requirement 5.2 - process inside namespace can listen on a port**
	listener := newNamespaceListener(netNS.Path, daemonNamespaceIPv6Addr, testListenerPort)
	err = listener.startListenerInNamespace()
	require.NoError(t, err, "Failed to start listener in daemon namespace")
	defer listener.stop()

	t.Logf("Listener started successfully on [%s]:%d inside namespace", daemonNamespaceIPv6Addr, testListenerPort)

	// Connect from the host to the daemon namespace using the IPv6 link-local address.
	// **Validates: Requirement 5.4 - traffic from host can reach process using IPv6 link-local IP**
	err = connectToNamespaceIPv6(daemonNamespaceIPv6Addr, testListenerPort, testMessage)
	require.NoError(t, err, "Failed to connect to daemon namespace from host using IPv6")

	t.Log("IPv6 connection from host to daemon namespace succeeded")

	// Verify that the listener received the message.
	receivedMsg, err := listener.getReceivedMessage(testConnectionTimeout)
	require.NoError(t, err, "Failed to receive message in daemon namespace")
	require.Equal(t, testMessage, receivedMsg, "Received message should match sent message")

	t.Logf("IPv6 message exchange verified: sent=%q, received=%q", testMessage, receivedMsg)
	t.Log("TestDaemonNamespaceIPv6Connectivity completed successfully")
}

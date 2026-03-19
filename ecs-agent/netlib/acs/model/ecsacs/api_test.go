// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

//go:build unit
// +build unit

package ecsacs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTypeAliasesAreUsable verifies that the type aliases defined in this
// package can be instantiated and used, confirming they correctly re-export
// the canonical types from ecs-agent/acs/model/ecsacs.
func TestTypeAliasesAreUsable(t *testing.T) {
	t.Parallel()

	t.Run("ElasticNetworkInterface", func(t *testing.T) {
		mac := "01:23:45:67:89:ab"
		eni := ElasticNetworkInterface{
			MacAddress: &mac,
		}
		assert.Equal(t, &mac, eni.MacAddress)
		assert.NotEmpty(t, eni.String())
		assert.Equal(t, eni.String(), eni.GoString())
	})

	t.Run("AckRequest", func(t *testing.T) {
		msgID := "msg-123"
		ack := AckRequest{
			MessageId: &msgID,
		}
		assert.Equal(t, &msgID, ack.MessageId)
		assert.NotEmpty(t, ack.String())
	})

	t.Run("ProxyConfiguration", func(t *testing.T) {
		proxyType := "APPMESH"
		proxy := ProxyConfiguration{
			Type: &proxyType,
		}
		assert.Equal(t, &proxyType, proxy.Type)
		assert.NotEmpty(t, proxy.String())
	})

	t.Run("Task", func(t *testing.T) {
		arn := "arn:aws:ecs:us-east-1:123456789012:task/my-task"
		task := Task{
			Arn: &arn,
		}
		assert.Equal(t, &arn, task.Arn)
		assert.NotEmpty(t, task.String())
	})
}

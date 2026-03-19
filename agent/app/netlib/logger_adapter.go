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

package netlib

import (
	agentlogger "github.com/aws/amazon-ecs-agent/ecs-agent/logger"
)

// LoggerAdapter implements netlib's logger.Logger interface
// (ecs-agent/netlib/internal/logger.Logger) by delegating to the agent's
// package-level logger functions.
//
// The netlib Logger interface requires:
//
//	Info(msg string, fields ...Fields)
//	Debug(msg string, fields ...Fields)
//	Warn(msg string, fields ...Fields)
//	Error(msg string, fields ...Fields)
//
// where Fields = map[string]interface{}.
//
// A compile-time interface assertion is not possible here because the
// Logger interface resides in netlib's internal/logger package, which
// Go's internal package rule restricts to the netlib module. The
// structural match is guaranteed by the method signatures below.
type LoggerAdapter struct{}

func (LoggerAdapter) Info(msg string, fields ...map[string]interface{}) {
	agentlogger.Info(msg, toAgentFields(fields)...)
}

func (LoggerAdapter) Debug(msg string, fields ...map[string]interface{}) {
	agentlogger.Debug(msg, toAgentFields(fields)...)
}

func (LoggerAdapter) Warn(msg string, fields ...map[string]interface{}) {
	agentlogger.Warn(msg, toAgentFields(fields)...)
}

func (LoggerAdapter) Error(msg string, fields ...map[string]interface{}) {
	agentlogger.Error(msg, toAgentFields(fields)...)
}

// toAgentFields converts a slice of map[string]interface{} (netlib's Fields
// type alias) to a slice of agentlogger.Fields (a named map type).
func toAgentFields(fields []map[string]interface{}) []agentlogger.Fields {
	result := make([]agentlogger.Fields, len(fields))
	for i, f := range fields {
		result[i] = agentlogger.Fields(f)
	}
	return result
}

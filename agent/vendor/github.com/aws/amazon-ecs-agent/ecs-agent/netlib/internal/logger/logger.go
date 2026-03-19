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

// Package logger provides a structured logging interface for netlib.
// It allows consumers to inject their own logging implementation while
// providing a no-op default that ensures safe operation when no logger is set.
package logger

// Fields is a type alias for structured log metadata.
type Fields = map[string]interface{}

// Field constants matching ecs-agent/logger/field values used by netlib.
const (
	TaskID     = "task"
	TaskARN    = "taskARN"
	ErrorField = "error"
)

// Logger defines the structured logging interface used by netlib.
type Logger interface {
	Info(msg string, fields ...Fields)
	Debug(msg string, fields ...Fields)
	Warn(msg string, fields ...Fields)
	Error(msg string, fields ...Fields)
}

// Package-level default (initialized to no-op).
var defaultLogger Logger = &nopLogger{}

// Set replaces the package-level default logger.
func Set(l Logger) {
	if l != nil {
		defaultLogger = l
	}
}

// Info logs a message at info level.
func Info(msg string, fields ...Fields) { defaultLogger.Info(msg, fields...) }

// Debug logs a message at debug level.
func Debug(msg string, fields ...Fields) { defaultLogger.Debug(msg, fields...) }

// Warn logs a message at warn level.
func Warn(msg string, fields ...Fields) { defaultLogger.Warn(msg, fields...) }

// Error logs a message at error level.
func Error(msg string, fields ...Fields) { defaultLogger.Error(msg, fields...) }

// nopLogger is the no-op implementation.
type nopLogger struct{}

func (*nopLogger) Info(string, ...Fields)  {}
func (*nopLogger) Debug(string, ...Fields) {}
func (*nopLogger) Warn(string, ...Fields)  {}
func (*nopLogger) Error(string, ...Fields) {}

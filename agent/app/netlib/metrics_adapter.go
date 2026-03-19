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
	agentmetrics "github.com/aws/amazon-ecs-agent/ecs-agent/metrics"
)

// metricsEntry mirrors netlib's internal/metrics.Entry interface.
// It is defined here so that the adapter return types structurally match
// the netlib interface, which cannot be imported due to Go's internal
// package rule.
type metricsEntry interface {
	WithFields(f map[string]interface{}) metricsEntry
	WithCount(count int) metricsEntry
	WithGauge(value interface{}) metricsEntry
	Done(err error)
}

// MetricsAdapter implements netlib's metrics.EntryFactory interface
// (ecs-agent/netlib/internal/metrics.EntryFactory) by delegating to the
// agent's metrics.EntryFactory.
//
// The netlib EntryFactory interface requires:
//
//	New(op string) Entry
//	Flush()
//
// A compile-time interface assertion is not possible here because the
// EntryFactory interface resides in netlib's internal/metrics package,
// which Go's internal package rule restricts to the netlib module. The
// structural match is guaranteed by the method signatures below.
type MetricsAdapter struct {
	delegate agentmetrics.EntryFactory
}

// NewMetricsAdapter creates a MetricsAdapter wrapping the given agent
// metrics EntryFactory.
func NewMetricsAdapter(ef agentmetrics.EntryFactory) *MetricsAdapter {
	return &MetricsAdapter{delegate: ef}
}

// New creates a new metric entry for the given operation name.
func (a *MetricsAdapter) New(op string) metricsEntry {
	return &entryAdapter{delegate: a.delegate.New(op)}
}

// Flush delegates to the wrapped factory's Flush method.
func (a *MetricsAdapter) Flush() {
	a.delegate.Flush()
}

// entryAdapter implements netlib's metrics.Entry interface
// (ecs-agent/netlib/internal/metrics.Entry) by delegating to the
// agent's metrics.Entry.
//
// The netlib Entry interface requires:
//
//	WithFields(f map[string]interface{}) Entry
//	WithCount(count int) Entry
//	WithGauge(value interface{}) Entry
//	Done(err error)
type entryAdapter struct {
	delegate agentmetrics.Entry
}

// WithFields sets metadata fields on the metric entry.
func (e *entryAdapter) WithFields(f map[string]interface{}) metricsEntry {
	return &entryAdapter{delegate: e.delegate.WithFields(f)}
}

// WithCount sets the count value on the metric entry.
func (e *entryAdapter) WithCount(count int) metricsEntry {
	return &entryAdapter{delegate: e.delegate.WithCount(count)}
}

// WithGauge sets the gauge value on the metric entry.
func (e *entryAdapter) WithGauge(value interface{}) metricsEntry {
	return &entryAdapter{delegate: e.delegate.WithGauge(value)}
}

// Done marks the metric operation as complete.
func (e *entryAdapter) Done(err error) {
	e.delegate.Done(err)
}

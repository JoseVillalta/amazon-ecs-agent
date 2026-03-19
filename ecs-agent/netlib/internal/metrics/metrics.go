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

package metrics

// EntryFactory creates metric entries.
type EntryFactory interface {
	New(op string) Entry
	Flush()
}

// Entry represents a single metric operation.
type Entry interface {
	WithFields(f map[string]interface{}) Entry
	WithCount(count int) Entry
	WithGauge(value interface{}) Entry
	Done(err error)
}

// Metric constants used by netlib.
const (
	BuildNetworkNamespaceMetricName  = "NetworkBuilder.BuildNetworkNamespace"
	DeleteNetworkNamespaceMetricName = "NetworkBuilder.DeleteNetworkNamespace"
)

// NopEntryFactory is a no-op implementation of EntryFactory.
type NopEntryFactory struct{}

func (*NopEntryFactory) New(string) Entry { return &nopEntry{} }
func (*NopEntryFactory) Flush()           {}

type nopEntry struct{}

func (e *nopEntry) WithFields(map[string]interface{}) Entry { return e }
func (e *nopEntry) WithCount(int) Entry                     { return e }
func (e *nopEntry) WithGauge(interface{}) Entry             { return e }
func (e *nopEntry) Done(error)                              {}

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

/*
Package netlib provides adapter types that bridge the ECS agent's
infrastructure (logging, metrics) to the interfaces expected by the
ecs-agent/netlib module.

# Adapters

LoggerAdapter implements netlib's internal/logger.Logger interface by
delegating to the agent's package-level logger functions in ecs-agent/logger.
It is a zero-field struct and can be used as a value (adapters.LoggerAdapter{}).

MetricsAdapter implements netlib's internal/metrics.EntryFactory interface by
wrapping the agent's metrics.EntryFactory. Create one with
NewMetricsAdapter(agentMetricsFactory).

# NetworkBuilder Wiring

The netlib.NewNetworkBuilder constructor accepts a logger.Logger and a
metrics.EntryFactory among its parameters. When the agent constructs a
NetworkBuilder, the adapters in this package should be passed as follows:

	import (
		"github.com/aws/amazon-ecs-agent/ecs-agent/netlib"
		adapters "github.com/aws/amazon-ecs-agent/agent/app/netlib"
	)

	builder, err := netlib.NewNetworkBuilder(
		platformCfg,
		adapters.NewMetricsAdapter(agentMetricsFactory),
		adapters.LoggerAdapter{},
		volumeAccessor,
		networkDAO,
		stateDBDir,
	)

Note: the agent does not yet call netlib.NewNetworkBuilder directly. This
documents the future wiring point so that when NetworkBuilder construction
is added, the correct adapter types are used.
*/
package netlib

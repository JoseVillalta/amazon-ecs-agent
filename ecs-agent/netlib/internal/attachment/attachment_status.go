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

package attachment

import (
	ecsattachment "github.com/aws/amazon-ecs-agent/ecs-agent/api/attachment"
)

// AttachmentStatus is a type alias for the canonical AttachmentStatus defined in
// ecs-agent/api/attachment. Using a type alias (=) ensures that this type IS
// the same Go type, resolving cross-module type mismatch errors.
type AttachmentStatus = ecsattachment.AttachmentStatus

const (
	// AttachmentNone is zero state of a task when received attach message from acs
	AttachmentNone = ecsattachment.AttachmentNone
	// AttachmentAttached represents that an attachment has shown on the host
	AttachmentAttached = ecsattachment.AttachmentAttached
	// AttachmentDetached represents that an attachment has been actually detached from the host
	AttachmentDetached = ecsattachment.AttachmentDetached
)

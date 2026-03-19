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

// Package ecsacs re-exports all types from the canonical ecsacs package
// (ecs-agent/acs/model/ecsacs) using type aliases. This ensures that netlib
// and ecs-agent share the same Go types, preventing type mismatch errors
// when netlib functions are called from ecs-agent code.
package ecsacs

import (
	canonical "github.com/aws/amazon-ecs-agent/ecs-agent/acs/model/ecsacs"
)

// Model types
type ASMAuthData = canonical.ASMAuthData
type AckRequest = canonical.AckRequest
type Association = canonical.Association
type AttachInstanceNetworkInterfacesMessage = canonical.AttachInstanceNetworkInterfacesMessage
type AttachTaskNetworkInterfacesMessage = canonical.AttachTaskNetworkInterfacesMessage
type Attachment = canonical.Attachment
type AttachmentProperty = canonical.AttachmentProperty
type CloseMessage = canonical.CloseMessage
type ConfirmAttachmentMessage = canonical.ConfirmAttachmentMessage
type Container = canonical.Container
type ContainerDependency = canonical.ContainerDependency
type Device = canonical.Device
type DockerConfig = canonical.DockerConfig
type DockerVolumeConfiguration = canonical.DockerVolumeConfiguration
type EBSVolumeConfiguration = canonical.EBSVolumeConfiguration
type ECRAuthData = canonical.ECRAuthData
type EFSAuthorizationConfig = canonical.EFSAuthorizationConfig
type EFSVolumeConfiguration = canonical.EFSVolumeConfiguration
type ElasticNetworkInterface = canonical.ElasticNetworkInterface
type EncodedString = canonical.EncodedString
type EnvironmentFile = canonical.EnvironmentFile
type ErrorMessage = canonical.ErrorMessage
type FSxWindowsFileServerAuthorizationConfig = canonical.FSxWindowsFileServerAuthorizationConfig
type FSxWindowsFileServerVolumeConfiguration = canonical.FSxWindowsFileServerVolumeConfiguration
type FirelensConfiguration = canonical.FirelensConfiguration
type HeartbeatAckRequest = canonical.HeartbeatAckRequest
type HeartbeatMessage = canonical.HeartbeatMessage
type HostVolumeProperties = canonical.HostVolumeProperties
type IAMRoleCredentials = canonical.IAMRoleCredentials
type IAMRoleCredentialsAckRequest = canonical.IAMRoleCredentialsAckRequest
type IAMRoleCredentialsMessage = canonical.IAMRoleCredentialsMessage
type IPv4AddressAssignment = canonical.IPv4AddressAssignment
type IPv6AddressAssignment = canonical.IPv6AddressAssignment
type KernelCapabilities = canonical.KernelCapabilities
type LinuxParameters = canonical.LinuxParameters
type ManagedAgent = canonical.ManagedAgent
type MountPoint = canonical.MountPoint
type NackRequest = canonical.NackRequest
type NetworkInterfaceTunnelProperties = canonical.NetworkInterfaceTunnelProperties
type NetworkInterfaceVethProperties = canonical.NetworkInterfaceVethProperties
type NetworkInterfaceVlanProperties = canonical.NetworkInterfaceVlanProperties
type PayloadMessage = canonical.PayloadMessage
type PerformUpdateMessage = canonical.PerformUpdateMessage
type PollRequest = canonical.PollRequest
type PortMapping = canonical.PortMapping
type ProxyConfiguration = canonical.ProxyConfiguration
type RegistryAuthenticationData = canonical.RegistryAuthenticationData
type RestartPolicy = canonical.RestartPolicy
type Secret = canonical.Secret
type StageUpdateMessage = canonical.StageUpdateMessage
type Task = canonical.Task
type TaskIdentifier = canonical.TaskIdentifier
type TaskManifestMessage = canonical.TaskManifestMessage
type TaskStopVerificationAck = canonical.TaskStopVerificationAck
type TaskStopVerificationMessage = canonical.TaskStopVerificationMessage
type UpdateInfo = canonical.UpdateInfo
type VersionInfo = canonical.VersionInfo
type Volume = canonical.Volume
type VolumeFrom = canonical.VolumeFrom

// Input/Output types
type AttachInstanceNetworkInterfacesInput = canonical.AttachInstanceNetworkInterfacesInput
type AttachInstanceNetworkInterfacesOutput = canonical.AttachInstanceNetworkInterfacesOutput
type AttachTaskNetworkInterfacesInput = canonical.AttachTaskNetworkInterfacesInput
type AttachTaskNetworkInterfacesOutput = canonical.AttachTaskNetworkInterfacesOutput
type ConfirmAttachmentInput = canonical.ConfirmAttachmentInput
type ConfirmAttachmentOutput = canonical.ConfirmAttachmentOutput
type ErrorInput = canonical.ErrorInput
type ErrorOutput = canonical.ErrorOutput
type HeartbeatInput = canonical.HeartbeatInput
type HeartbeatOutput = canonical.HeartbeatOutput
type PayloadInput = canonical.PayloadInput
type PayloadOutput = canonical.PayloadOutput
type PerformUpdateInput = canonical.PerformUpdateInput
type PerformUpdateOutput = canonical.PerformUpdateOutput
type PollInput = canonical.PollInput
type PollOutput = canonical.PollOutput
type RefreshTaskIAMRoleCredentialsInput = canonical.RefreshTaskIAMRoleCredentialsInput
type RefreshTaskIAMRoleCredentialsOutput = canonical.RefreshTaskIAMRoleCredentialsOutput
type StageUpdateInput = canonical.StageUpdateInput
type StageUpdateOutput = canonical.StageUpdateOutput
type TaskManifestInput = canonical.TaskManifestInput
type TaskManifestOutput = canonical.TaskManifestOutput
type TaskStopVerificationInput = canonical.TaskStopVerificationInput
type TaskStopVerificationOutput = canonical.TaskStopVerificationOutput
type UpdateFailureInput = canonical.UpdateFailureInput
type UpdateFailureOutput = canonical.UpdateFailureOutput

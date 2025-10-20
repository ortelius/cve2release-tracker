// Package model - Endpoint defines the struct for deployment targets
package model

// EndpointType represents the type of deployment target
type EndpointType string

const (
	// Cloud and Container Infrastructure
	EndpointTypeCluster EndpointType = "cluster"
	EndpointTypeEC2     EndpointType = "ec2"
	EndpointTypeLambda  EndpointType = "lambda"
	EndpointTypeECS     EndpointType = "ecs"
	EndpointTypeEKS     EndpointType = "eks"
	EndpointTypeGKE     EndpointType = "gke"
	EndpointTypeAKS     EndpointType = "aks"
	EndpointTypeFargate EndpointType = "fargate"

	// Edge and IoT Devices
	EndpointTypeEdge EndpointType = "edge"
	EndpointTypeIoT  EndpointType = "iot"

	// Mission Assets - Military and Defense
	EndpointTypeMissionAsset EndpointType = "mission_asset"
)

// Endpoint represents a deployment target for syncing releases
type Endpoint struct {
	Key          string       `json:"_key,omitempty"`
	Name         string       `json:"name"`
	EndpointType EndpointType `json:"endpoint_type"`
	Environment  string       `json:"environment"`
	ObjType      string       `json:"objtype,omitempty"`
}

// NewEndpoint creates a new Endpoint instance with default values
func NewEndpoint() *Endpoint {
	return &Endpoint{
		ObjType: "Endpoint",
	}
}

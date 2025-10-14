// Package model - PURL defines the struct for Package URL documents.
package model

// PURL represents a package URL document in the purl collection
type PURL struct {
	Key     string `json:"_key,omitempty"`
	Purl    string `json:"purl"` // Cleaned/canonical PURL without qualifiers and subpath
	ObjType string `json:"objtype,omitempty"`
}

// NewPURL is the constructor that sets the appropriate default values
func NewPURL() *PURL {
	return &PURL{ObjType: "PURL"}
}

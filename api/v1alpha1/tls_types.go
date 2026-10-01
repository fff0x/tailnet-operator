package v1alpha1

// TLSIssuerReference identifies a cert-manager issuer without requiring its API dependency.
// Issuer references resolve in the ingress namespace; ClusterIssuer references are cluster-scoped.
type TLSIssuerReference struct {
	// Name of the issuer.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
	// +optional
	// +kubebuilder:default=Issuer
	// +kubebuilder:validation:Enum=Issuer;ClusterIssuer
	Kind string `json:"kind,omitempty"`
	// Only cert-manager.io issuers are supported.
	// +optional
	// +kubebuilder:default="cert-manager.io"
	// +kubebuilder:validation:Enum=cert-manager.io
	Group string `json:"group,omitempty"`
}

// IngressTLS selects the HTTP certificate source. An explicit Secret suppresses the Tailnet's
// default issuer. With neither field set, the ingress may inherit the Tailnet's default issuer.
// +kubebuilder:validation:XValidation:rule="!has(self.secretName) || !has(self.issuerRef)",message="tls.secretName and tls.issuerRef are mutually exclusive"
type IngressTLS struct {
	// Existing TLS Secret in the ingress namespace.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	SecretName string `json:"secretName,omitempty"`
	// +optional
	IssuerRef *TLSIssuerReference `json:"issuerRef,omitempty"`
}

// TLSDefaults supplies an issuer for HTTP ingresses without an explicit TLS source.
// Secrets are namespace-local and cannot be selected as a Tailnet-wide default.
type TLSDefaults struct {
	// +optional
	IssuerRef *TLSIssuerReference `json:"issuerRef,omitempty"`
}

// TailnetDefaults supplies optional defaults for resources referencing a Tailnet.
type TailnetDefaults struct {
	// +optional
	TLS *TLSDefaults `json:"tls,omitempty"`
}

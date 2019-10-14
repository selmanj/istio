// GENERATED FILE -- DO NOT EDIT
//

package msg

import (
	"istio.io/istio/galley/pkg/config/analysis/diag"
	"istio.io/istio/galley/pkg/config/resource"
)

var (
	// InternalError defines a diag.MessageType for message "InternalError".
	// Description: There was an internal error in the toolchain. This is almost always a bug in the implementation.
	InternalError = diag.NewMessageType(diag.Error, "IST0001", "Internal error: %v")

	// NotYetImplemented defines a diag.MessageType for message "NotYetImplemented".
	// Description: A feature that the configuration is depending on is not implemented yet.
	NotYetImplemented = diag.NewMessageType(diag.Error, "IST0002", "Not yet implemented: %s")

	// ParseError defines a diag.MessageType for message "ParseError".
	// Description: There was a parse error during the parsing of the configuration text
	ParseError = diag.NewMessageType(diag.Warning, "IST0003", "Parse error: %s")

	// Deprecated defines a diag.MessageType for message "Deprecated".
	// Description: A feature that the configuration is depending on is now deprecated.
	Deprecated = diag.NewMessageType(diag.Warning, "IST0004", "Deprecated: %s")

	// ReferencedResourceNotFound defines a diag.MessageType for message "ReferencedResourceNotFound".
	// Description: A resource being referenced does not exist.
	ReferencedResourceNotFound = diag.NewMessageType(diag.Error, "IST0101", "Referenced %s not found: %q")

	// NamespaceNotInjected defines a diag.MessageType for message "NamespaceNotInjected".
	// Description: A namespace is not enabled for Istio injection.
	NamespaceNotInjected = diag.NewMessageType(diag.Warning, "IST0102", "The namespace is not enabled for Istio injection. Run 'kubectl label namespace %s istio-injection=enabled' to enable it, or 'kubectl label namespace %s istio-injection=disabled' to explicitly mark it as not needing injection")

	// PodMissingProxy defines a diag.MessageType for message "PodMissingProxy".
	// Description: A pod is missing the Istio proxy.
	PodMissingProxy = diag.NewMessageType(diag.Warning, "IST0103", "The pod is missing its Istio proxy. Run 'kubectl delete pod %s -n %s' to restart it")

	// GatewayPortNotOnWorkload defines a diag.MessageType for message "GatewayPortNotOnWorkload".
	// Description: Unhandled gateway port
	GatewayPortNotOnWorkload = diag.NewMessageType(diag.Warning, "IST0104", "The gateway refers to a port that is not exposed on the workload (pod selector %s; port %d)")

	// IstioProxyVersionMismatch defines a diag.MessageType for message "IstioProxyVersionMismatch".
	// Description: The version of the Istio proxy running on the pod does not match the version used by the istio injector.
	IstioProxyVersionMismatch = diag.NewMessageType(diag.Warning, "IST0105", "The version of the Istio proxy running on the pod does not match the version used by the istio injector (pod version: %s; injector version: %s). This often happens after upgrading the Istio control-plane and can be fixed by redeploying the pod.")

	// SchemaValidationError defines a diag.MessageType for message "SchemaValidationError".
	// Description: The resource has one or more schema validation errors.
	SchemaValidationError = diag.NewMessageType(diag.Error, "IST0106", "The resource has one or more schema validation errors: %v")
	
	// GatewayOverlaps defines a diag.MessageType for message "GatewayOverlaps".
	// Description: Gateway's server overlaps with another Gateway.
	GatewayOverlaps = diag.NewMessageType(diag.Warning, "IST0107", "The gateway's server on port %d with host %s overlaps with %s with host %s. Only one will take effect.")
)

// NewInternalError returns a new diag.Message based on InternalError.
func NewInternalError(entry *resource.Entry, detail string) diag.Message {
	return diag.NewMessage(
		InternalError,
		originOrNil(entry),
		detail,
	)
}

// NewNotYetImplemented returns a new diag.Message based on NotYetImplemented.
func NewNotYetImplemented(entry *resource.Entry, detail string) diag.Message {
	return diag.NewMessage(
		NotYetImplemented,
		originOrNil(entry),
		detail,
	)
}

// NewParseError returns a new diag.Message based on ParseError.
func NewParseError(entry *resource.Entry, detail string) diag.Message {
	return diag.NewMessage(
		ParseError,
		originOrNil(entry),
		detail,
	)
}

// NewDeprecated returns a new diag.Message based on Deprecated.
func NewDeprecated(entry *resource.Entry, detail string) diag.Message {
	return diag.NewMessage(
		Deprecated,
		originOrNil(entry),
		detail,
	)
}

// NewReferencedResourceNotFound returns a new diag.Message based on ReferencedResourceNotFound.
func NewReferencedResourceNotFound(entry *resource.Entry, reftype string, refval string) diag.Message {
	return diag.NewMessage(
		ReferencedResourceNotFound,
		originOrNil(entry),
		reftype,
		refval,
	)
}

// NewNamespaceNotInjected returns a new diag.Message based on NamespaceNotInjected.
func NewNamespaceNotInjected(entry *resource.Entry, namespace string, namespace2 string) diag.Message {
	return diag.NewMessage(
		NamespaceNotInjected,
		originOrNil(entry),
		namespace,
		namespace2,
	)
}

// NewPodMissingProxy returns a new diag.Message based on PodMissingProxy.
func NewPodMissingProxy(entry *resource.Entry, pod string, namespace string) diag.Message {
	return diag.NewMessage(
		PodMissingProxy,
		originOrNil(entry),
		pod,
		namespace,
	)
}

// NewGatewayPortNotOnWorkload returns a new diag.Message based on GatewayPortNotOnWorkload.
func NewGatewayPortNotOnWorkload(entry *resource.Entry, selector string, port int) diag.Message {
	return diag.NewMessage(
		GatewayPortNotOnWorkload,
		originOrNil(entry),
		selector,
		port,
	)
}

<<<<<<< HEAD
// NewIstioProxyVersionMismatch returns a new diag.Message based on IstioProxyVersionMismatch.
func NewIstioProxyVersionMismatch(entry *resource.Entry, proxyVersion string, injectionVersion string) diag.Message {
	return diag.NewMessage(
		IstioProxyVersionMismatch,
		originOrNil(entry),
		proxyVersion,
		injectionVersion,
	)
}

<<<<<<< HEAD
<<<<<<< HEAD
// NewSchemaValidationError returns a new diag.Message based on SchemaValidationError.
func NewSchemaValidationError(entry *resource.Entry, combinedErr error) diag.Message {
	return diag.NewMessage(
		SchemaValidationError,
		originOrNil(entry),
		combinedErr,
=======
=======
>>>>>>> 359dc9d29... WIP: basic infra in place
// NewMultipleGatewaysOverlapSameHostPort returns a new diag.Message based on MultipleGatewaysOverlapSameHostPort.
func NewMultipleGatewaysOverlapSameHostPort(entry *resource.Entry, gateways string, hostnames string, port int) diag.Message {
=======
// NewGatewayOverlaps returns a new diag.Message based on GatewayOverlaps.
func NewGatewayOverlaps(entry *resource.Entry, port uint32, host string, otherGateway string, otherHost string) diag.Message {
>>>>>>> 76dc83754... WIP: Nearly done, but needs more tests
	return diag.NewMessage(
		GatewayOverlaps,
		originOrNil(entry),
		port,
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> d4b29dd37... WIP: Add new message, analyzer
=======
>>>>>>> 359dc9d29... WIP: basic infra in place
=======
		host,
		otherGateway,
		otherHost,
>>>>>>> 76dc83754... WIP: Nearly done, but needs more tests
	)
}

func originOrNil(e *resource.Entry) resource.Origin {
	var o resource.Origin
	if e != nil {
		o = e.Origin
	}
	return o
}

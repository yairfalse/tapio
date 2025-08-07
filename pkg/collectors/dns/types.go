package dns

import "time"

// DNSQueryType represents different DNS record types
type DNSQueryType uint16

const (
	DNSTypeA     DNSQueryType = 1
	DNSTypeAAAA  DNSQueryType = 28
	DNSTypeCNAME DNSQueryType = 5
	DNSTypeMX    DNSQueryType = 15
	DNSTypeTXT   DNSQueryType = 16
	DNSTypePTR   DNSQueryType = 12
	DNSTypeSOA   DNSQueryType = 6
	DNSTypeNS    DNSQueryType = 2
)

// DNSResponseCode represents DNS response codes
type DNSResponseCode uint8

const (
	DNSRCodeNoError  DNSResponseCode = 0 // NOERROR
	DNSRCodeFormErr  DNSResponseCode = 1 // FORMERR
	DNSRCodeServFail DNSResponseCode = 2 // SERVFAIL
	DNSRCodeNXDomain DNSResponseCode = 3 // NXDOMAIN
	DNSRCodeNotImpl  DNSResponseCode = 4 // NOTIMP
	DNSRCodeRefused  DNSResponseCode = 5 // REFUSED
)

// DNSProtocol represents the transport protocol used
type DNSProtocol uint8

const (
	DNSProtocolUDP DNSProtocol = 17
	DNSProtocolTCP DNSProtocol = 6
)

// DNSEventType represents the type of DNS event
type DNSEventType uint8

const (
	DNSEventQuery    DNSEventType = 1
	DNSEventResponse DNSEventType = 2
	DNSEventError    DNSEventType = 3
	DNSEventTimeout  DNSEventType = 4
)

// DNSFailureType categorizes different types of DNS failures
type DNSFailureType string

const (
	FailureTypeTimeout       DNSFailureType = "timeout"
	FailureTypeNXDomain      DNSFailureType = "nxdomain"
	FailureTypeServerFailure DNSFailureType = "servfail"
	FailureTypeRefused       DNSFailureType = "refused"
	FailureTypeNetworkError  DNSFailureType = "network_error"
	FailureTypeUnknown       DNSFailureType = "unknown"
)

// CorrelatedDNSEvent represents a fully correlated DNS query-response pair
type CorrelatedDNSEvent struct {
	Query          *DNSEvent
	Response       *DNSEvent
	ResponseTime   time.Duration
	Success        bool
	FailureType    DNSFailureType
	CorrelationKey string
}

// DNSFailureContext provides additional context for DNS failures
type DNSFailureContext struct {
	Domain              string
	ResolverIP          string
	ProcessInfo         ProcessInfo
	KubernetesContext   *KubernetesContext
	NetworkInterface    string
	FailureFrequency    int
	LastSuccessfulQuery time.Time
}

// ProcessInfo contains information about the process making the DNS query
type ProcessInfo struct {
	PID         uint32
	PPID        uint32
	ProcessName string
	CommandLine string
	UserID      uint32
	GroupID     uint32
}

// KubernetesContext provides Kubernetes-specific context
type KubernetesContext struct {
	Namespace     string
	PodName       string
	PodUID        string
	ContainerName string
	ServiceName   string
	Labels        map[string]string
	Annotations   map[string]string
	NodeName      string
}

// DNSMetrics represents metrics collected by the DNS collector
type DNSMetrics struct {
	TotalQueries      uint64
	TotalResponses    uint64
	FailedQueries     uint64
	TimeoutQueries    uint64
	SlowQueries       uint64
	AverageLatency    time.Duration
	TopFailedDomains  map[string]uint64
	FailuresByType    map[DNSFailureType]uint64
	QueriesByResolver map[string]uint64
}

// DNSCollectorEvent represents a high-level DNS event sent to the pipeline
type DNSCollectorEvent struct {
	Timestamp         time.Time
	EventID           string
	EventType         DNSEventType
	FailureType       DNSFailureType
	Domain            string
	QueryType         DNSQueryType
	ResponseCode      DNSResponseCode
	Protocol          DNSProtocol
	SourceIP          string
	DestinationIP     string
	ResponseTime      time.Duration
	ProcessInfo       ProcessInfo
	KubernetesContext *KubernetesContext
	RawDNSData        []byte
	Metadata          map[string]string
}

// String methods for better debugging and logging

func (qt DNSQueryType) String() string {
	switch qt {
	case DNSTypeA:
		return "A"
	case DNSTypeAAAA:
		return "AAAA"
	case DNSTypeCNAME:
		return "CNAME"
	case DNSTypeMX:
		return "MX"
	case DNSTypeTXT:
		return "TXT"
	case DNSTypePTR:
		return "PTR"
	case DNSTypeSOA:
		return "SOA"
	case DNSTypeNS:
		return "NS"
	default:
		return "UNKNOWN"
	}
}

func (rc DNSResponseCode) String() string {
	switch rc {
	case DNSRCodeNoError:
		return "NOERROR"
	case DNSRCodeFormErr:
		return "FORMERR"
	case DNSRCodeServFail:
		return "SERVFAIL"
	case DNSRCodeNXDomain:
		return "NXDOMAIN"
	case DNSRCodeNotImpl:
		return "NOTIMP"
	case DNSRCodeRefused:
		return "REFUSED"
	default:
		return "UNKNOWN"
	}
}

func (p DNSProtocol) String() string {
	switch p {
	case DNSProtocolUDP:
		return "UDP"
	case DNSProtocolTCP:
		return "TCP"
	default:
		return "UNKNOWN"
	}
}

func (et DNSEventType) String() string {
	switch et {
	case DNSEventQuery:
		return "QUERY"
	case DNSEventResponse:
		return "RESPONSE"
	case DNSEventError:
		return "ERROR"
	case DNSEventTimeout:
		return "TIMEOUT"
	default:
		return "UNKNOWN"
	}
}

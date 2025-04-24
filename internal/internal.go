package internal

type SnmpVersion uint8

const (
	Version1  SnmpVersion = 0x1
	Version2c SnmpVersion = 0x2
	Version3  SnmpVersion = 0x3
)

// SNMPChecker generic interface for snmp scanning
// helps to define generic wait for interface
type SNMPChecker interface {
	GetInput() []Input
	ProduceOutput(<-chan Output, chan<- struct{})
}

// Input represent the input
type Input struct {
	IP              string      `json:"ip"`
	Tag             string      `json:"tag,omitempty"`
	Version         SnmpVersion `json:"version,omitempty"`
	Community       string      `json:"community,omitempty"`
	Oids            []string    `json:"oids,omitempty"`
	Timeout         int         `json:"timeout,omitempty"`
	Retries         int         `json:"retries,omitempty"`
	Port            int         `json:"port,omitempty"`
	SecurityLevel   string      `json:"security_level,omitempty"`
	UserName        string      `json:"user_name,omitempty"`
	AuthType        string      `json:"auth_type,omitempty"`
	AuthPass        string      `json:"auth_pass,omitempty"`
	PrivType        string      `json:"priv_type,omitempty"`
	PrivPass        string      `json:"priv_pass,omitempty"`
	ContextName     string      `json:"context_name,omitempty"`
	ContextEngineID string      `json:"context_engineid,omitempty"`
	CustomType      string      `json:"custom_type,omitempty"`
}

// Data represent the snmp result
type Data struct {
	Value interface{} `json:"value"`
	Name  string      `json:"name"`
	Type  string      `json:"type"`
}

// Output represent the output result
type Output struct {
	I    Input  `json:"input"`
	Err  string `json:"error,omitempty"`
	Data []Data `json:"data"`
}

type SNMPOperation uint8

const (
	GET      SNMPOperation = 0x1
	WALK     SNMPOperation = 0x2
	BULKWALK SNMPOperation = 0x3
)

// CmdPipe helps to process commandline args
type CmdPipe struct {
	InputFile  string
	OutputFile string
	NoWokers   int
	Reties     int
	JsonType   bool
	Version    string
	Timeout    int
	Oids       []string
	Port       int
	Operation  SNMPOperation
	AppVersion bool
}

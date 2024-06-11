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
	IP        string      `json:"ip"`
	Community string      `json:"community,omitempty"`
	Tag       string      `json:"tag,omitempty"`
	Version   SnmpVersion `json:"version,omitempty"`
	Oids      []string    `json:"oids,omitempty"`
	Timeout   int         `json:"timeout,omitempty"`
	Retries   int         `json:"retries,omitempty"`
	Port      int         `json:"port,omitempty"`
	UserName  string      `json:"user_name,omitempty"`
	AuthType  string      `json:"auth_type,omitempty"`
	AuthPass  string      `json:"auth_pass,omitempty"`
	PrivType  string      `json:"priv_type,omitempty"`
	PrivPass  string      `json:"priv_pass,omitempty"`
}

// Data represent the snmp result
type Data struct {
	Value interface{} `json:"value"`
	Name  string      `json:"name"`
}

// Output represent the output result
type Output struct {
	I    Input  `json:"input"`
	Err  string `json:"error,omitempty"`
	Data []Data `json:"data"`
}

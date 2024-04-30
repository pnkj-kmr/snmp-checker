package internal

import (
	"fmt"
	"log"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// GetSNMP_V2C helps to perform snmp v2c and return the grouped result
func GetSNMP_V2C(ip, community string, oids []string, port, timeout uint16) (out []string, err error) {
	//
	//	snmpwalk -v 2c -c <community> <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//
	if port == 0 {
		port = 161
	}
	if community == "" {
		community = "public"
	}
	if timeout == 0 {
		timeout = 3
	}
	if len(oids) == 0 {
		oids = []string{"1.3.6.1.2.1.1.1.0"}
	}

	inst := &g.GoSNMP{
		Target:             ip,
		Port:               port,
		Transport:          "udp",
		Community:          community,
		Version:            g.Version2c,
		Timeout:            time.Duration(timeout) * time.Second,
		ExponentialTimeout: true,
		MaxOids:            60,
	}

	err = inst.Connect()
	if err != nil {
		log.Println("SNMP connection err", err)
		return
	}
	defer inst.Conn.Close()

	result, err := inst.Get(oids)
	if err != nil {
		log.Println("SNMP get result err", err)
		return
	}

	for _, variable := range result.Variables {
		out = append(out, fmt.Sprintf("%s: %s", variable.Name, variable.Value))
	}
	return
}

// GetSNMP_V3 helps to perform snmp v3 and return the grouped result
func GetSNMP_V3(ip, username, authtype, authpass, privtype, privpass string, oids []string, port, timeout uint16) (out []string, err error) {
	//
	// snmpwalk -v 3 -l <level> -u <username> -a <authtype> -x <privtype> -A <authpass> -X <privpass>  <target> <oid>
	//
	/*
		TODO - need to handle snmp v3 properly as per auth and priv types
	*/

	if port == 0 {
		port = 161
	}
	if timeout == 0 {
		timeout = 3
	}
	if len(oids) == 0 {
		oids = []string{"1.3.6.1.2.1.1.1.0"}
	}
	aType := g.MD5
	if authtype == "SHA" {
		aType = g.SHA
	}
	pType := g.AES
	if privtype == "DES" {
		pType = g.DES
	}

	inst := &g.GoSNMP{
		Target:        ip,
		Port:          port,
		Version:       g.Version3,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		Timeout:       time.Duration(timeout) * time.Second,
		SecurityParameters: &g.UsmSecurityParameters{
			UserName:                 username,
			AuthenticationProtocol:   aType,
			AuthenticationPassphrase: authpass,
			PrivacyProtocol:          pType,
			PrivacyPassphrase:        privpass,
		},
	}

	err = inst.Connect()
	if err != nil {
		log.Println("SNMP connection err", err)
		return
	}
	defer inst.Conn.Close()

	result, err := inst.Get(oids)
	if err != nil {
		log.Println("SNMP get result err", err)
		return
	}

	for _, variable := range result.Variables {
		out = append(out, fmt.Sprintf("%s: %s", variable.Name, variable.Value))
	}
	return
}

package internal

import (
	"log"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// SNMP_v1 helps to perform snmp v1 and return the grouped result
func SNMP_v1(i Input, port uint16, walkFlag bool) (out Output, err error) {
	//
	//	snmpwalk -v 1 <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//
	var _port uint16 = uint16(i.Port)
	if _port == 0 {
		if port == 0 {
			port = 161
		}
		_port = port
	}
	var community string = i.Community
	if community == "" {
		community = "public"
	}
	var timeout int = i.Timeout
	if timeout == 0 {
		timeout = 5
	}

	inst := &g.GoSNMP{
		Target:             i.IP,
		Port:               _port,
		Transport:          "udp",
		Community:          community,
		Version:            g.Version1,
		Timeout:            time.Duration(timeout) * time.Second,
		ExponentialTimeout: true,
		MaxOids:            60,
		Retries:            i.Retries,
	}

	err = inst.Connect()
	if err != nil {
		log.Println("SNMP connection err", err)
		return
	}
	defer inst.Conn.Close()

	var data []Data
	if walkFlag {
		data, err = snmpWalk(inst, i.Oids[0], i.CustomType)
		if err != nil {
			return
		}
	} else {
		data, err = snmpGet(inst, i.Oids, i.CustomType)
		if err != nil {
			return
		}
	}
	return Output{I: i, Err: "", Data: data}, nil
}

// SNMP_v2c helps to perform snmp v2c and return the grouped result
func SNMP_v2c(i Input, port uint16, walkFlag bool) (out Output, err error) {
	//
	//	snmpwalk -v 2c -c <community> <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//
	var _port uint16 = uint16(i.Port)
	if _port == 0 {
		if port == 0 {
			port = 161
		}
		_port = port
	}
	var community string = i.Community
	if community == "" {
		community = "public"
	}
	var timeout int = i.Timeout
	if timeout == 0 {
		timeout = 5
	}

	inst := &g.GoSNMP{
		Target:             i.IP,
		Port:               _port,
		Transport:          "udp",
		Community:          community,
		Version:            g.Version2c,
		Timeout:            time.Duration(timeout) * time.Second,
		ExponentialTimeout: true,
		MaxOids:            60,
		Retries:            i.Retries,
	}

	err = inst.Connect()
	if err != nil {
		log.Println("SNMP connection err", err)
		return
	}
	defer inst.Conn.Close()

	var data []Data
	if walkFlag {
		data, err = snmpBulkWalk(inst, i.Oids[0], i.CustomType)
		if err != nil {
			return
		}
	} else {
		data, err = snmpGet(inst, i.Oids, i.CustomType)
		if err != nil {
			return
		}
	}
	return Output{I: i, Err: "", Data: data}, nil
}

// SNMP_v3 helps to perform snmp v3 and return the grouped result
func SNMP_v3(i Input, port uint16, walkFlag bool) (out Output, err error) {
	//
	// snmpwalk -v 3 -l <level> -u <username> -a <authtype> -x <privtype> -A <authpass> -X <privpass>  <target> <oid>
	//
	/*
		TODO - need to handle snmp v3 properly as per auth and priv types
	*/

	var _port uint16 = uint16(i.Port)
	if _port == 0 {
		if port == 0 {
			port = 161
		}
		_port = port
	}

	var timeout int = i.Timeout
	if timeout == 0 {
		timeout = 5
	}

	var msg_flag string = i.SecurityLevel
	if msg_flag == "" {
		msg_flag = "AuthPriv"
	}

	inst := &g.GoSNMP{
		Target:             i.IP,
		Port:               _port,
		Version:            g.Version3,
		SecurityModel:      g.UserSecurityModel,
		MsgFlags:           getMsgFlag(msg_flag),
		Timeout:            time.Duration(timeout) * time.Second,
		ExponentialTimeout: true,
		MaxOids:            60,
		Retries:            i.Retries,
		SecurityParameters: &g.UsmSecurityParameters{
			UserName:                 i.UserName,
			AuthenticationProtocol:   getAuthType(i.AuthType),
			AuthenticationPassphrase: i.AuthPass,
			PrivacyProtocol:          getPrivType(i.PrivType),
			PrivacyPassphrase:        i.PrivPass,
		},
		ContextEngineID: i.ContextEngineID,
		ContextName:     i.ContextName,
	}

	err = inst.Connect()
	if err != nil {
		log.Println("SNMP connection err", err)
		return
	}
	defer inst.Conn.Close()

	var data []Data
	if walkFlag {
		data, err = snmpBulkWalk(inst, i.Oids[0], i.CustomType)
		if err != nil {
			return
		}
	} else {
		data, err = snmpGet(inst, i.Oids, i.CustomType)
		if err != nil {
			return
		}
	}
	return Output{I: i, Err: "", Data: data}, nil
}

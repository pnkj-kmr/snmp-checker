package internal

import (
	"log/slog"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// SNMP helps to perform snmp operation and return the grouped result
func SNMP(i Input, cmd CmdPipe) (out Output, err error) {
	inst := getSNMPInstance(i, cmd)
	err = inst.Connect()
	if err != nil {
		slog.Warn("SNMP connection", "error", err)
		return
	}
	defer inst.Conn.Close()
	return doSNMP(inst, i, cmd.Operation)
}

// SNMPSync helps to perform snmp operation and return the grouped result
func SNMPSync(inputs []Input, cmd CmdPipe) (out []Output, err error) {
	inst := getSNMPInstance(inputs[0], cmd)
	err = inst.Connect()
	if err != nil {
		slog.Warn("SNMP connection", "error", err)
		return
	}
	defer inst.Conn.Close()

	// looping over smae ip resources
	for _, i := range inputs {
		o, _err := doSNMP(inst, i, cmd.Operation)
		if _err != nil {
			return out, _err
		}
		out = append(out, o)
		if cmd.SyncSleep != 0 {
			time.Sleep(time.Duration(cmd.SyncSleep) * time.Millisecond)
		}
	}
	return
}

func doSNMP(inst *g.GoSNMP, i Input, oper SNMPOperation) (out Output, err error) {
	out.I = i
	var data []Data
	switch oper {
	case BULKWALK:
		data, err = snmpBulkWalk(inst, i.Oids[0], i.CustomType)
		if err != nil {
			out.Err = err.Error()
			return
		}
	case WALK:
		data, err = snmpWalk(inst, i.Oids[0], i.CustomType)
		if err != nil {
			out.Err = err.Error()
			return
		}
	default:
		data, err = snmpGet(inst, i.Oids, i.CustomType)
		if err != nil {
			out.Err = err.Error()
			return
		}
	}
	out.Data = data
	return
}

func getSNMPInstance(i Input, cmd CmdPipe) *g.GoSNMP {
	version := getVersion(i.Version)
	switch version {
	case g.Version1:
		return getV1(i, cmd)

	case g.Version2c:
		return getV2C(i, cmd)

	case g.Version3:
		return getV3(i, cmd)

	default:
		return getV2C(i, cmd)
	}
}

func getV1(i Input, cmd CmdPipe) *g.GoSNMP {
	//
	//	snmpwalk -v 1 <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//
	var maxOids = 60
	var _port uint16 = uint16(i.Port)
	if _port == 0 {
		_port = uint16(cmd.Port)
	}
	var community string = i.Community
	if community == "" {
		community = "public"
	}
	if cmd.EncodingEnabled {
		community = Decode(community)
	}
	var timeout int = i.Timeout
	if timeout == 0 {
		timeout = cmd.Timeout
	}
	var retries = i.Retries
	if retries > 3 {
		retries = 3
	}

	inst := &g.GoSNMP{
		Target:             i.IP,
		Port:               _port,
		Transport:          "udp",
		Community:          community,
		Version:            g.Version1,
		Timeout:            time.Duration(timeout) * time.Second,
		ExponentialTimeout: true,
		MaxOids:            maxOids,
		Retries:            retries,
	}
	return inst
}

func getV2C(i Input, cmd CmdPipe) *g.GoSNMP {
	//
	//	snmpwalk -v 2c -c <community> <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//
	var maxOids = 60
	var _port uint16 = uint16(i.Port)
	if _port == 0 {
		_port = uint16(cmd.Port)
	}
	var community string = i.Community
	if community == "" {
		community = "public"
	}
	if cmd.EncodingEnabled {
		community = Decode(community)
	}
	var timeout int = i.Timeout
	if timeout == 0 {
		timeout = cmd.Timeout
	}
	var retries = i.Retries
	if retries > 3 {
		retries = 3
	}

	inst := &g.GoSNMP{
		Target:             i.IP,
		Port:               _port,
		Transport:          "udp",
		Community:          community,
		Version:            g.Version2c,
		Timeout:            time.Duration(timeout) * time.Second,
		ExponentialTimeout: true,
		MaxOids:            maxOids,
		Retries:            retries,
	}
	return inst
}

func getV3(i Input, cmd CmdPipe) *g.GoSNMP {
	//
	// snmpwalk -v 3 -l <level> -u <username> -a <authtype> -x <privtype> -A <authpass> -X <privpass>  <target> <oid>
	//
	var maxOids = 60
	var _port uint16 = uint16(i.Port)
	if _port == 0 {
		_port = uint16(cmd.Port)
	}
	var timeout int = i.Timeout
	if timeout == 0 {
		timeout = cmd.Timeout
	}
	var retries = i.Retries
	if retries > 3 {
		retries = 3
	}
	var msgFlag string = i.SecurityLevel
	if msgFlag == "" {
		msgFlag = "AuthPriv"
	}
	authPass := i.AuthPass
	if cmd.EncodingEnabled {
		authPass = Decode(i.AuthPass)
	}
	privPass := i.PrivPass
	if cmd.EncodingEnabled {
		privPass = Decode(i.PrivPass)
	}

	inst := &g.GoSNMP{
		Target:             i.IP,
		Port:               _port,
		Version:            g.Version3,
		SecurityModel:      g.UserSecurityModel,
		MsgFlags:           getMsgFlag(msgFlag),
		Timeout:            time.Duration(timeout) * time.Second,
		ExponentialTimeout: true,
		MaxOids:            maxOids,
		Retries:            retries,
		SecurityParameters: &g.UsmSecurityParameters{
			UserName:                 i.UserName,
			AuthenticationProtocol:   getAuthType(i.AuthType),
			AuthenticationPassphrase: authPass,
			PrivacyProtocol:          getPrivType(i.PrivType),
			PrivacyPassphrase:        privPass,
		},
		ContextEngineID: i.ContextEngineID,
		ContextName:     i.ContextName,
	}
	return inst
}

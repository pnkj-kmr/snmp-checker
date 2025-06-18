package internal

import (
	"log/slog"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// SNMP_v1 helps to perform snmp v1 and return the grouped result
func SNMP_v1(i Input, cmd CmdPipe) (out Output, err error) {
	//
	//	snmpwalk -v 1 <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//
	inst := getSNMPInstance(i, cmd)
	err = inst.Connect()
	if err != nil {
		slog.Warn("SNMP connection", "error", err)
		return
	}
	defer inst.Conn.Close()
	return doSNMP(inst, i, cmd.Operation)
}

// SNMP_v2c helps to perform snmp v2c and return the grouped result
func SNMP_v2c(i Input, cmd CmdPipe) (out Output, err error) {
	//
	//	snmpwalk -v 2c -c <community> <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//
	inst := getSNMPInstance(i, cmd)
	err = inst.Connect()
	if err != nil {
		slog.Warn("SNMP connection", "error", err)
		return
	}
	defer inst.Conn.Close()
	return doSNMP(inst, i, cmd.Operation)
}

// SNMP_v3 helps to perform snmp v3 and return the grouped result
func SNMP_v3(i Input, cmd CmdPipe) (out Output, err error) {
	//
	// snmpwalk -v 3 -l <level> -u <username> -a <authtype> -x <privtype> -A <authpass> -X <privpass>  <target> <oid>
	//
	/*
		TODO - need to handle snmp v3 properly as per auth and priv types
	*/
	inst := getSNMPInstance(i, cmd)
	err = inst.Connect()
	if err != nil {
		slog.Warn("SNMP connection", "error", err)
		return
	}
	defer inst.Conn.Close()
	return doSNMP(inst, i, cmd.Operation)
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
	//
	//	snmpwalk -v 1 <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	//	snmpwalk -v 2c -c <community> <target> <oid (i.e. 1.3.6.1.2.1.1.3.0)>
	// 	snmpwalk -v 3 -l <level> -u <username> -a <authtype> -x <privtype> -A <authpass> -X <privpass>  <target> <oid>
	//

	var _port uint16 = uint16(i.Port)
	if _port == 0 {
		_port = uint16(cmd.Port)
	}
	var community string = i.Community
	if community == "" {
		community = "public"
	}
	var timeout int = i.Timeout
	if timeout == 0 {
		timeout = cmd.Timeout
	}
	var msgFlag string = i.SecurityLevel
	if msgFlag == "" {
		msgFlag = "AuthPriv"
	}
	// we are not allowing more than 3 retries of a IP
	// helps to reducs the poll cycle
	var retries = i.Retries
	if retries > 3 {
		retries = 3
	}
	var maxOids = 60

	version := getVersion(i.Version)

	_snmp := g.Default

	_snmp.Target = ""
	_snmp.Port = _port
	_snmp.Retries = retries
	_snmp.Timeout = time.Duration(timeout) * time.Second
	_snmp.MaxOids = maxOids
	_snmp.ExponentialTimeout = true
	_snmp.Version = version

	switch version {
	case g.Version1:
		_snmp.Transport = "udp"
		_community := i.Community
		if cmd.EncodingEnabled {
			_community = Decode(i.Community)
		}
		_snmp.Community = _community
	case g.Version2c:
		_snmp.Transport = "udp"
		_community := i.Community
		if cmd.EncodingEnabled {
			_community = Decode(i.Community)
		}
		_snmp.Community = _community
	case g.Version3:
		_authPass := i.AuthPass
		if cmd.EncodingEnabled {
			_authPass = Decode(i.AuthPass)
		}
		_privPass := i.PrivPass
		if cmd.EncodingEnabled {
			_privPass = Decode(i.PrivPass)
		}

		_snmp.SecurityModel = g.UserSecurityModel
		_snmp.MsgFlags = getMsgFlag(msgFlag)
		_snmp.SecurityParameters = &g.UsmSecurityParameters{
			UserName:                 i.UserName,
			AuthenticationProtocol:   getAuthType(i.AuthType),
			AuthenticationPassphrase: _authPass,
			PrivacyProtocol:          getPrivType(i.PrivType),
			PrivacyPassphrase:        _privPass,
		}
		_snmp.ContextName = i.ContextName
		if i.ContextEngineID != "" {
			_snmp.ContextEngineID = i.ContextEngineID
		}
	}

	return _snmp
}

package internal

import (
	"flag"
	"strings"

	g "github.com/gosnmp/gosnmp"
)

func getMsgFlag(s string) g.SnmpV3MsgFlags {
	switch s {
	case "NoAuthNoPriv":
		return g.NoAuthNoPriv
	case "AuthNoPriv":
		return g.AuthNoPriv
	case "AuthPriv":
		return g.AuthPriv
	case "Reportable":
		return g.Reportable
	default:
		return g.NoAuthNoPriv
	}
}

func getAuthType(s string) g.SnmpV3AuthProtocol {
	switch s {
	case "MD5":
		return g.MD5
	case "SHA":
		return g.SHA
	case "SHA224", "SHA-224":
		return g.SHA224
	case "SHA256", "SHA-256":
		return g.SHA256
	case "SHA384", "SHA-384":
		return g.SHA384
	case "SHA512", "SHA-512":
		return g.SHA512
	default:
		return g.NoAuth
	}
}

func getPrivType(s string) g.SnmpV3PrivProtocol {
	switch s {
	case "DES":
		return g.DES
	case "AES", "AES-128":
		return g.AES
	case "AES192", "AES-192":
		return g.AES192
	case "AES256", "AES-256":
		return g.AES256
	case "AES192C", "AES-192C":
		return g.AES192C
	case "AES256C", "AES-256C":
		return g.AES256C
	default:
		return g.NoPriv
	}
}

func GetCmdPipe() CmdPipe {

	fileName := flag.String("f", "input.csv", "give a file name")
	outFilename := flag.String("o", "output.csv", "output file name")
	noWorkers := flag.Int("w", 4, "number of worker")
	retries := flag.Int("r", 0, "retries")
	jsontype := flag.Bool("json", false, "file type - default[csv]")
	version := flag.String("v", "2c", "SNMP version (1 / 2c / 3)")
	timeout := flag.Int("t", 5, "snmp timeout [secs]")
	oid := flag.String("oid", "1.3.6.1.2.1.1.1.0", "snmp walk oid (multiple -oid 'oid1 oid2 oid3')")
	port := flag.Int("port", 161, "snmp port")
	snmpOperation := flag.String("operation", "GET", "for snmp operations GET/WALK/BULKWALK")
	flag.Parse()

	oids := strings.Split((*oid), " ")
	var operation SNMPOperation
	switch *snmpOperation {
	case "WALK":
		operation = WALK
	case "BULKWALK":
		operation = BULKWALK
	default:
		operation = GET
	}

	return CmdPipe{
		InputFile:  *fileName,
		OutputFile: *outFilename,
		NoWokers:   *noWorkers,
		Reties:     *retries,
		JsonType:   *jsontype,
		Version:    *version,
		Timeout:    *timeout,
		Oids:       oids,
		Port:       *port,
		Operation:  operation,
	}
}

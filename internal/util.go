package internal

import (
	"encoding/base64"
	"flag"
	"strings"

	g "github.com/gosnmp/gosnmp"
)

func getVersion(v int) g.SnmpVersion {
	switch v {
	case 1:
		return g.Version1
	case 2:
		return g.Version2c
	case 3:
		return g.Version3
	default:
		return g.Version2c
	}
}

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
	appVersion := flag.Bool("version", false, "Application Version")
	fileName := flag.String("f", "input.csv", "Input Filename")
	outFilename := flag.String("o", "output.csv", "Output Filename")
	noWorkers := flag.Int("w", 10, "Number of Worker Threads")
	retries := flag.Int("r", 0, "Retries")
	jsontype := flag.Bool("json", false, "File Type - default[csv]")
	timeout := flag.Int("t", 5, "SNMP Timeout [secs]")
	oid := flag.String("oid", "1.3.6.1.2.1.1.1.0", "SNMPp Default Oid (multiple -oid 'oid1 oid2 oid3')")
	port := flag.Int("port", 161, "SNMP Port")
	snmpOperation := flag.String("operation", "GET", "SNMP Operations GET/WALK/BULKWALK")
	debug := flag.Bool("debug", false, "Log Level - default[false]")
	encodingEnabled := flag.Bool("encoding", false, "Encoding - default[false]")
	syncFetch := flag.Bool("sync", false, "Syncronize (Group by IP) - default[false]")
	syncFetchSleep := flag.Int("sync_sleep", 0, "Sycronize Sleep Interval [msecs]")
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
		InputFile:       *fileName,
		OutputFile:      *outFilename,
		NoWokers:        *noWorkers,
		Reties:          *retries,
		JsonType:        *jsontype,
		Timeout:         *timeout,
		Oids:            oids,
		Port:            *port,
		Operation:       operation,
		AppVersion:      *appVersion,
		Debug:           *debug,
		EncodingEnabled: *encodingEnabled,
		SyncFetch:       *syncFetch,
		SyncSleep:       *syncFetchSleep,
	}
}

func Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func Decode(s string) string {
	d, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(d)
}

func groupByIP(data []Input) (out map[string][]Input) {
	grouped := make(map[string][]Input)
	for _, i := range data {
		grouped[i.IP] = append(grouped[i.IP], i)
	}
	return grouped
}

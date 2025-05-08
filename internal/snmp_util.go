package internal

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"unicode"
	"unicode/utf8"

	g "github.com/gosnmp/gosnmp"
)

func snmpGet(inst *g.GoSNMP, Oids []string, customType string) (data []Data, err error) {
	result, err := inst.Get(Oids)
	if err != nil {
		log.Println("SNMP GET err", err)
		return
	}
	for _, v := range result.Variables {
		data = append(data, parseData(v, customType))
	}
	return
}

func snmpWalk(inst *g.GoSNMP, Oid, customType string) (data []Data, err error) {
	// size calculation
	//for one value in []Data 16 bytes(interface{}) + 16 bytes (string) + 16 bytes (string) = 48 bytes
	// for 1000 it will be 48*100 = 4800 bytes and plus slice header space is 24 bytes
	// so overall ~4.6Kb

	data = make([]Data, 0, 300) // preallocation of memory help in performance boost. As memory reallocation happens less
	var callback = func(d g.SnmpPDU) error {
		data = append(data, parseData(d, customType))
		return nil
	}
	err = inst.Walk(Oid, callback)
	if err != nil {
		log.Println("SNMP WALK err", err)
		return
	}
	return
}

func snmpBulkWalk(inst *g.GoSNMP, Oid, customType string) (data []Data, err error) {
	data = make([]Data, 0, 300) // preallocation of memory help in performance boost. As memory reallocation happens less
	var callback = func(d g.SnmpPDU) error {
		data = append(data, parseData(d, customType))
		return nil
	}
	err = inst.BulkWalk(Oid, callback)
	if err != nil {
		log.Println("SNMP BULK WALK err", err)
		return
	}
	return
}

func parseData(d g.SnmpPDU, customType string) (data Data) {
	switch d.Type {
	case g.Integer, g.Counter32, g.Gauge32, g.TimeTicks, g.Counter64, g.Uinteger32:
		data = Data{Name: d.Name, Value: g.ToBigInt(d.Value), Type: pduTypeToString(d.Type)}
	case g.OctetString:
		b, ok := d.Value.([]byte)
		if !ok || b == nil {
			data = Data{Name: d.Name, Value: "", Type: "STRING"}
			break
		}
		value, new_type := parseOctetString(b, customType)
		data = Data{Name: d.Name, Value: value, Type: new_type}
	default:
		// default value should be string and type should be specified
		strVal, ok := d.Value.(string)
		if !ok {
			strVal = fmt.Sprintf("%v", d.Value)
		}
		data = Data{Name: d.Name, Value: strVal, Type: pduTypeToString(d.Type)}
	}
	return
}

func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printableCount := 0
	for _, b := range data {
		if unicode.IsPrint(rune(b)) {
			printableCount++
		}
	}
	return float64(printableCount)/float64(len(data)) > 0.8
}

func formHexBytesWithSpaces(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, " ")
}

func parseOctetString(value []byte, customType string) (string, string) {

	if customType == "MAC" {
		var macAddress strings.Builder
		for i, b := range value {
			if i > 0 {
				macAddress.WriteString(":")
			}
			macAddress.WriteString(fmt.Sprintf("%02X", b))
		}
		return macAddress.String(), "MAC"
	} else if customType == "STRING" {
		return string(value), "STRING"
	}

	if isMostlyPrintable(value) && utf8.Valid(value) {
		str := string(value)
		if decoded, err := hex.DecodeString(str); err == nil && isMostlyPrintable(decoded) {
			return string(decoded), "Hex-STRING"
		}
		return str, "STRING"
	}

	if len(value) == 6 {
		var macAddress strings.Builder
		for i, b := range value {
			if i > 0 {
				macAddress.WriteString(":")
			}
			macAddress.WriteString(fmt.Sprintf("%02X", b))
		}
		return macAddress.String(), "MAC"
	}

	return formHexBytesWithSpaces(value), "Hex-STRING"
}

func pduTypeToString(t g.Asn1BER) string {
	switch t {
	case g.Boolean:
		return "Boolean"
	case g.Integer:
		return "Integer"
	case g.BitString:
		return "BitString"
	case g.OctetString:
		return "OctetString"
	case g.Null:
		return "Null"
	case g.ObjectIdentifier:
		return "ObjectIdentifier"
	case g.IPAddress:
		return "IPAddress"
	case g.Counter32:
		return "Counter32"
	case g.Gauge32:
		return "Gauge32"
	case g.TimeTicks:
		return "TimeTicks"
	case g.Opaque:
		return "Opaque"
	case g.NsapAddress:
		return "NsapAddress"
	case g.Counter64:
		return "Counter64"
	case g.Uinteger32:
		return "Uinteger32"
	case g.NoSuchObject:
		return "NoSuchObject"
	case g.NoSuchInstance:
		return "NoSuchInstance"
	case g.EndOfMibView:
		return "EndOfMibView"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

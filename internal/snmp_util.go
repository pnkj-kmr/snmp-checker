package internal

import (
	"fmt"
	"log"
	"strings"

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
	case g.IPAddress:
		ip := d.Value.(string)
		data = Data{Name: d.Name, Value: ip, Type: d.Type}
	case g.OctetString:
		b := d.Value.([]byte)
		data = Data{Name: d.Name, Value: parseOctetString(b, customType), Type: d.Type}
	default:
		data = Data{Name: d.Name, Value: g.ToBigInt(d.Value), Type: d.Type}
	}
	return
}

func parseOctetString(value []byte, customType string) string {
	// TODO len==6
	//if customType == "HEXA" {
	// return fmt.Sprintf("%02X", []byte(value))

	if customType == "MAC" {
		var macAddress strings.Builder
		for i, b := range value {
			if i > 0 {
				macAddress.WriteString(":")
			}
			macAddress.WriteString(fmt.Sprintf("%02X", b))
		}
		return macAddress.String()
	} else if customType == "STRING" {
		return string(value)
	}

	if len(value) == 6 {
		var macAddress strings.Builder
		for i, b := range value {
			if i > 0 {
				macAddress.WriteString(":")
			}
			macAddress.WriteString(fmt.Sprintf("%02X", b))
		}
		return macAddress.String()
	}
	return string(value)
}

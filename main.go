package main

import (
	_ "embed"
	"fmt"
	"log"
	"snmp-checker/internal"
	"sync"
	"time"
)

//go:embed version.txt
var appVersion string

func main() {
	st := time.Now()
	cmdPipe := internal.GetCmdPipe()

	log.Println("file accepted:", cmdPipe.InputFile, "| output file:", cmdPipe.OutputFile)
	log.Println("timeout:", cmdPipe.Timeout, "| workers:", cmdPipe.NoWokers, "| port:", cmdPipe.Port, "| version:", cmdPipe.Version, "| oids:", cmdPipe.Oids)
	log.Println("snmp operation:", cmdPipe.Operation, "| json:", cmdPipe.JsonType)

	if cmdPipe.AppVersion {
		log.Println("Version: ", appVersion)
		return
	}

	// SNMPChecker object instance
	var snmpchecker internal.SNMPChecker
	if cmdPipe.Version == "2c" {
		if cmdPipe.JsonType {
			snmpchecker = internal.NewV2C_json(cmdPipe)
		} else {

			snmpchecker = internal.NewV2C(cmdPipe)
		}
	} else if cmdPipe.Version == "3" {
		if cmdPipe.JsonType {
			snmpchecker = internal.NewV3_json(cmdPipe)
		} else {
			snmpchecker = internal.NewV3(cmdPipe)
		}
	} else if cmdPipe.Version == "1" {
		if cmdPipe.JsonType {
			snmpchecker = internal.NewV1_json(cmdPipe)
		} else {
			snmpchecker = internal.NewV1(cmdPipe)
		}
	} else {
		log.Fatal("Unsupported SNMP version")
	}

	records := snmpchecker.GetInput()
	log.Println("Total IPs :", len(records))

	exitChan := make(chan struct{})
	ch := make(chan internal.Output, cmdPipe.NoWokers)
	go snmpchecker.ProduceOutput(ch, exitChan)

	var wg sync.WaitGroup
	c := make(chan int, cmdPipe.NoWokers)
	for i := 0; i < len(records); i++ {
		wg.Add(1)
		c <- 1
		go func(i internal.Input, ind, port int, oper internal.SNMPOperation) {
			defer func() { wg.Done(); <-c }()
			// fmt.Println("ip--- ", ip)
			var r internal.Output
			var err error
			if i.Version == internal.Version2c {
				r, err = internal.SNMP_v2c(i, uint16(port), oper)
			} else if i.Version == internal.Version3 {
				r, err = internal.SNMP_v3(i, uint16(port), oper)
			} else if i.Version == internal.Version1 {
				r, err = internal.SNMP_v1(i, uint16(port), oper)
			}
			if err == nil {
				err = fmt.Errorf("")
				r.Err = err.Error()
			} else {
				r = internal.Output{I: i, Err: err.Error(), Data: []internal.Data{}}
			}
			// fmt.Println("--------result------", r, err)
			ch <- r
		}(records[i], i, cmdPipe.Port, cmdPipe.Operation)
		log.Println("IP sent for SNMP -- ", records[i], i+1)
	}
	wg.Wait()
	close(ch)
	<-exitChan
	log.Println("Execution completed. time taken", time.Since(st))
}

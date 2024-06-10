package main

import (
	"flag"
	"fmt"
	"log"
	"snmp-checker/internal"
	"strings"
	"sync"
)

func main() {
	fileName := flag.String("f", "input.csv", "give a file name")
	outFilename := flag.String("o", "output.csv", "output file name")
	noWorkers := flag.Int("w", 4, "number of worker")
	retries := flag.Int("r", 0, "retries")
	jsontype := flag.Bool("json", false, "file type - default[csv]")
	version := flag.String("v", "2c", "SNMP version (2c / 3)")
	timeout := flag.Int("t", 5, "snmp timeout [secs]")
	oid := flag.String("oid", "1.3.6.1.2.1.1.1.0", "snmp walk oid (multiple -oid 'oid1 oid2 oid3')")
	port := flag.Int("port", 161, "snmp port")
	flag.Parse()
	oids := strings.Split((*oid), " ")

	log.Println("file accepted:", *fileName, "| output file:", *outFilename)
	log.Println("timeout:", *timeout, "| worker processes:", *noWorkers, "| port:", *port, "| oids:", oids)

	// SNMPChecker object instance
	var snmpchecker internal.SNMPChecker
	if *version == "2c" {
		if *jsontype {
			snmpchecker = internal.NewJSONV2C(*fileName, *outFilename, *retries, *timeout, oids)
		} else {

			snmpchecker = internal.NewV2C(*fileName, *outFilename, *retries, *timeout, oids)
		}
	} else if *version == "3" {
		if *jsontype {
			snmpchecker = internal.NewJSONV3(*fileName, *outFilename, *retries, *timeout, oids)
		} else {
			snmpchecker = internal.NewV3(*fileName, *outFilename, *retries, *timeout, oids)
		}
	} else {
		log.Fatal("Unsupported SNMP version")
	}

	records := snmpchecker.GetInput()
	log.Println("Total IPs :", len(records))

	exitChan := make(chan struct{})
	ch := make(chan internal.Output, *noWorkers)
	go snmpchecker.ProduceOutput(ch, exitChan)

	var wg sync.WaitGroup
	c := make(chan int, *noWorkers)
	for i := 0; i < len(records); i++ {
		wg.Add(1)
		c <- 1
		go func(i internal.Input, ind, port int) {
			defer func() { wg.Done(); <-c }()
			// fmt.Println("ip--- ", ip)
			// var ok bool
			// var err error
			var r internal.Output
			var err error
			if i.Version == internal.Version2c {
				r, err = internal.GetSNMP_V2C(i, uint16(port))
			} else if i.Version == internal.Version3 {
				r, err = internal.GetSNMP_V3(i, uint16(port))
			}
			if err == nil {
				err = fmt.Errorf("")
				r.Err = err.Error()
			} else {
				r = internal.Output{I: i, Err: err.Error(), Data: []internal.Data{}}
			}
			// fmt.Println("--------result------", r, err)
			ch <- r
		}(records[i], i, *port)
		log.Println("IP sent for SNMP -- ", records[i], i+1)
	}
	wg.Wait()
	close(ch)
	<-exitChan
	log.Println("Execution completed.")
}

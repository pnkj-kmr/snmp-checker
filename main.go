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
	timeout := flag.Int("t", 5, "snmp timeout - secs")
	oid := flag.String("oid", "1.3.6.1.2.1.1.1.0", "snmp walk oid (multiple -oid 'oid1 oid2 oid3')")
	port := flag.Int("port", 161, "snmp port")

	flag.Parse()
	// if *fileName == "" {
	// 	*fileName = "./input.csv"
	// }
	oids := strings.Split((*oid), " ")
	log.Println("file accepted:", *fileName, "| output file:", *outFilename)
	log.Println("timeout:", *timeout, "| worker processes:", *noWorkers, "| port:", *port, "| oids:", oids)

	ipsV2c, ipsV3 := internal.GetIPList(*fileName)
	log.Println("Total IPs -- v2c:", len(ipsV2c), "v3:", len(ipsV3))

	exitChan := make(chan struct{})
	ch := make(chan internal.Output)
	go internal.PutOutput(*outFilename, ch, exitChan)

	var wg sync.WaitGroup
	c := make(chan int, *noWorkers)
	// v2c loop
	for i := 0; i < len(ipsV2c); i++ {
		wg.Add(1)
		c <- 1
		go func(ip internal.InputV2C, oids []string, i, t, port int) {
			defer func() { wg.Done(); <-c }()
			// fmt.Println("ip--- ", ip)
			// var ok bool
			// var err error
			r, err := internal.GetSNMP_V2C(ip.IP, ip.Community, oids, uint16(port), uint16(t))
			if err == nil {
				err = fmt.Errorf("")
			}
			// fmt.Println("ip--- ", ip, ok, err)
			ch <- internal.Output{IP: ip.IP, Tag: ip.Community, Result: r, Err: err}
		}(ipsV2c[i], oids, i, *timeout, *port)
		log.Println("IP sent for SNMP -- ", ipsV2c[i], i+1)
	}
	// v3 loop
	for i := 0; i < len(ipsV3); i++ {
		wg.Add(1)
		c <- 1
		go func(ip internal.InputV3, oids []string, i, t, port int) {
			defer func() { wg.Done(); <-c }()
			// fmt.Println("ip--- ", ip)
			// var ok bool
			// var err error
			r, err := internal.GetSNMP_V3(ip.IP, ip.UserName, ip.AuthType, ip.AuthPass, ip.PrivType, ip.PrivPass, oids, uint16(port), uint16(t))
			if err == nil {
				err = fmt.Errorf("")
			}
			// fmt.Println("ip--- ", ip, ok, err)
			ch <- internal.Output{IP: ip.IP, Tag: ip.UserName, Result: r, Err: err}
		}(ipsV3[i], oids, i, *timeout, *port)
		log.Println("IP sent for SNMP -- ", ipsV3[i], i+1)
	}

	wg.Wait()
	close(ch)
	<-exitChan
	log.Println("Execution completed.")
}

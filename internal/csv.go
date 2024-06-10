package internal

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
)

type _csv struct {
	ifile   string
	ofile   string
	version SnmpVersion
	retries int
	timeout int
	oids    []string
}

func NewV2C(ifile, ofile string, retries, timeout int, oids []string) SNMPChecker {
	return &_csv{
		ifile, ofile, Version2c, retries, timeout, oids,
	}
}

func NewV3(ifile, ofile string, retries, timeout int, oids []string) SNMPChecker {
	return &_csv{
		ifile, ofile, Version3, retries, timeout, oids,
	}
}

func (c *_csv) GetInput() (out []Input) {
	file, err := os.Open(c.ifile)
	if err != nil {
		log.Fatal("Error while reading the file", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatal("Error while Error reading records", err)
	}
	// TODO - mutliple oid IP specific case
	var oids []string
	if len(c.oids) == 0 {
		oids = []string{"1.3.6.1.2.1.1.1.0"}
	} else {
		oids = c.oids
	}

	for _, r := range records {
		if len(r) == 2 {
			//<ip>,<community>
			out = append(out, Input{
				IP:        r[0],
				Community: r[1],
				Tag:       "", // TODO - tag into csv
				Version:   c.version,
				Oids:      oids,
				Timeout:   c.timeout,
				Retries:   c.retries,
				UserName:  "",
				AuthType:  "",
				AuthPass:  "",
				PrivType:  "",
				PrivPass:  "",
			})
		} else if len(r) == 6 {
			// <ip>,snmpv3usr,MD5,Enoc@thpk,AES,Airtel@thpk
			out = append(out, Input{
				IP:        r[0],
				Community: "",
				Tag:       "", // TODO - tag into csv
				Version:   c.version,
				Oids:      oids,
				Timeout:   c.timeout,
				Retries:   c.retries,
				UserName:  r[1],
				AuthType:  r[2],
				AuthPass:  r[3],
				PrivType:  r[4],
				PrivPass:  r[5],
			})
		}
	}
	return out
}

func (c *_csv) ProduceOutput(ch <-chan Output, exitCh chan<- struct{}) {
	file, err := os.Create(fmt.Sprintf("./%s", c.ofile))
	if err != nil {
		log.Fatal("Unable to write into file", err)
	}
	defer file.Close()
	file.Write([]byte("ip,tag,oid,value,error_if_any\n"))
	for r := range ch {
		if len(r.Data) != 0 {
			for _, variable := range r.Data {
				file.Write([]byte(fmt.Sprintf("%s,%s,%s,%v,%s\n", r.I.IP, r.I.Tag, variable.Name, variable.Value, r.Err)))
			}
		} else {
			file.Write([]byte(fmt.Sprintf("%s,%s,,,%s\n", r.I.IP, r.I.Tag, r.Err)))

		}
	}
	exitCh <- struct{}{}
}

package internal

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

type _json struct {
	ifile   string
	ofile   string
	version SnmpVersion
	retries int
	timeout int
	oids    []string
	port    int
}

func NewV1_json(c CmdPipe) SNMPChecker {
	return &_json{
		c.InputFile, c.OutputFile, Version1, c.Reties, c.Timeout, c.Oids, c.Port,
	}
}

func NewV2C_json(c CmdPipe) SNMPChecker {
	return &_json{
		c.InputFile, c.OutputFile, Version2c, c.Reties, c.Timeout, c.Oids, c.Port,
	}
}

func NewV3_json(c CmdPipe) SNMPChecker {
	return &_json{
		c.InputFile, c.OutputFile, Version3, c.Reties, c.Timeout, c.Oids, c.Port,
	}
}

func (j *_json) GetInput() (out []Input) {
	fileData, err := os.ReadFile(j.ifile)
	if err != nil {
		log.Fatal("Error while read the json file", err)
	}

	err = json.Unmarshal(fileData, &out)
	if err != nil {
		log.Fatal("Error while converting to json", err)
	}

	var oids []string
	if len(j.oids) == 0 {
		oids = []string{"1.3.6.1.2.1.1.1.0"}
	} else {
		oids = j.oids
	}

	var outnew []Input
	for _, d := range out {
		if d.Version == 0 {
			d.Version = j.version
		}
		if len(d.Oids) == 0 {
			d.Oids = oids
		}
		if d.Timeout == 0 {
			d.Timeout = j.timeout
		}
		if d.Retries == 0 {
			d.Retries = j.retries
		}
		if d.Port == 0 {
			d.Port = j.port
		}
		outnew = append(outnew, d)
	}
	return outnew
}

func (j *_json) ProduceOutput(ch <-chan Output, exitCh chan<- struct{}) {
	var out []Output
	for r := range ch {
		out = append(out, r)
	}

	outJson, _ := json.Marshal(out)
	err := ioutil.WriteFile(fmt.Sprintf("%s", j.ofile), outJson, 0644)
	if err != nil {
		log.Fatal("Error while writing into file", err)
	}

	exitCh <- struct{}{}
}

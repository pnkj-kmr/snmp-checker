package internal

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
)

type _json struct {
	ifile   string
	ofile   string
	retries int
	timeout int
	oids    []string
	port    int
}

func NewJSON(c CmdPipe) SNMPChecker {
	return &_json{
		c.InputFile, c.OutputFile, c.Reties, c.Timeout, c.Oids, c.Port,
	}
}

func (j *_json) GetInput() (out []Input) {
	fileData, err := os.ReadFile(j.ifile)
	if err != nil {
		slog.Error("Error while read the json file", "error", err)
		os.Exit(1)
	}

	err = json.Unmarshal(fileData, &out)
	if err != nil {
		slog.Error("Error while converting to json", "error", err)
		os.Exit(1)
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
			d.Version = 2
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
	err := os.WriteFile(fmt.Sprintf("%s", j.ofile), outJson, 0644)
	if err != nil {
		slog.Error("Error while writing into file", "error", err)
		os.Exit(1)
	}

	exitCh <- struct{}{}
}

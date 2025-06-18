package main

import (
	_ "embed"
	"fmt"
	"log/slog"
	"snmp-checker/internal"
	"sync"
	"time"
)

//go:embed version.txt
var appVersion string

func main() {
	st := time.Now()
	cmdPipe := internal.GetCmdPipe()

	if cmdPipe.Debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if cmdPipe.AppVersion {
		slog.Warn("snmp-checker", "version", appVersion)
		return
	}

	slog.Info("default configuration(s)...",
		"input_file", cmdPipe.InputFile, "output_file", cmdPipe.OutputFile,
		"timeout", cmdPipe.Timeout, "no_of_workers", cmdPipe.NoWokers,
		"port", cmdPipe.Port, "oids", cmdPipe.Oids, "operation", cmdPipe.Operation,
		"json", cmdPipe.JsonType, "debug", cmdPipe.Debug, "encoding_enabled", cmdPipe.EncodingEnabled,
	)

	// SNMPChecker object instance
	var snmpchecker internal.SNMPChecker
	if cmdPipe.JsonType {
		snmpchecker = internal.NewJSON(cmdPipe)
	} else {
		snmpchecker = internal.NewCSV(cmdPipe)
	}

	records := snmpchecker.GetInput()
	slog.Info("total records...", "count", len(records))

	exitChan := make(chan struct{})
	ch := make(chan internal.Output, cmdPipe.NoWokers)
	go snmpchecker.ProduceOutput(ch, exitChan)

	var wg sync.WaitGroup
	c := make(chan int, cmdPipe.NoWokers)
	for i := 0; i < len(records); i++ {
		wg.Add(1)
		c <- 1
		go func(i internal.Input, ind int, cmdPipe internal.CmdPipe) {
			defer func() { wg.Done(); <-c }()
			var r internal.Output
			var err error
			switch i.Version {
			case 1:
				r, err = internal.SNMP_v1(i, cmdPipe)
			case 2:
				r, err = internal.SNMP_v2c(i, cmdPipe)
			case 3:
				r, err = internal.SNMP_v1(i, cmdPipe)
			}
			if err == nil {
				err = fmt.Errorf("")
				r.Err = err.Error()
			} else {
				r = internal.Output{I: i, Err: err.Error(), Data: []internal.Data{}}
			}
			ch <- r
		}(records[i], i, cmdPipe)
		slog.Debug("SNMP configuration trigger...", "record", records[i], "counter", i+1)
	}
	wg.Wait()
	close(ch)
	<-exitChan
	slog.Info("Execution completed...", "time_taken", time.Since(st))
}

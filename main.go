package main

import (
	_ "embed"
	"log/slog"
	"snmp-checker/internal"
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

	// make required channel
	exitChan := make(chan struct{})
	ch := make(chan internal.Output, cmdPipe.NoWokers)

	// running output builder
	go snmpchecker.ProduceOutput(ch, exitChan)

	// main executor function
	internal.Execute(records, cmdPipe, ch)

	close(ch)
	<-exitChan
	slog.Info("Execution completed...", "time_taken", time.Since(st))
}

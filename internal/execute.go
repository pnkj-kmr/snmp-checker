package internal

import (
	"fmt"
	"log/slog"
	"sync"
)

func Execute(records []Input, cmdPipe CmdPipe, ch chan Output) {
	if cmdPipe.SyncFetch {
		recordMap := groupByIP(records)
		executeSync(recordMap, cmdPipe, ch)
		return
	}

	var wg sync.WaitGroup
	c := make(chan int, cmdPipe.NoWokers)
	for i := 0; i < len(records); i++ {
		wg.Add(1)
		c <- 1
		go func(i Input, ind int, cmdPipe CmdPipe) {
			defer func() { wg.Done(); <-c }()
			// calling SNMP
			r, err := SNMP(i, cmdPipe)
			if err == nil {
				err = fmt.Errorf("")
				r.Err = err.Error()
			} else {
				r = Output{I: i, Err: err.Error(), Data: []Data{}}
			}
			ch <- r
		}(records[i], i, cmdPipe)
		slog.Debug("SNMP configuration trigger...", "record", records[i], "counter", i+1)
	}
	wg.Wait()
}

func executeSync(records map[string][]Input, cmdPipe CmdPipe, ch chan Output) {
	var wg sync.WaitGroup
	c := make(chan int, cmdPipe.NoWokers)
	i := 0
	for ip, data := range records {
		wg.Add(1)
		c <- 1
		go func(inputs []Input, ip string, cmdPipe CmdPipe) {
			defer func() { wg.Done(); <-c }()
			// calling SNMPSync
			out, err := SNMPSync(inputs, cmdPipe)
			if err == nil {
				err = fmt.Errorf("")
				for _, r := range out {
					r.Err = err.Error()
					ch <- r
				}
			} else {
				for _, i := range inputs {
					ch <- Output{I: i, Err: err.Error(), Data: []Data{}}
				}
			}
		}(data, ip, cmdPipe)
		i = i + len(data)
		slog.Debug("SNMP configuration trigger...", "record", data[0], "counter", i)
	}
	wg.Wait()
}

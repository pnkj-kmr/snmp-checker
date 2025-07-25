package internal

import (
	"encoding/csv"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type _csv struct {
	ifile   string
	ofile   string
	retries int
	timeout int
	oids    []string
	port    int
}

func NewCSV(c CmdPipe) SNMPChecker {
	return &_csv{
		c.InputFile, c.OutputFile, c.Reties, c.Timeout, c.Oids, c.Port,
	}
}

func (c *_csv) GetInput() (out []Input) {
	file, err := os.Open(c.ifile)
	if err != nil {
		slog.Error("Error while reading the file", "error", err)
		os.Exit(1)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		slog.Error("Error while Error reading records", "error", err)
		os.Exit(1)
	}

	var oids []string
	if len(c.oids) == 0 {
		oids = []string{"1.3.6.1.2.1.1.1.0"}
	} else {
		oids = c.oids
	}

	var rowInput Input
	headers := make(map[int]string)
	for i, r := range records {
		if i == 0 {
			// creating header mapping
			for j, col := range r {
				headers[j] = col
			}
			continue
		}
		// forming input
		for j, val := range r {
			switch headers[j] {
			case "ip":
				rowInput.IP = val
			case "tag":
				rowInput.Tag = val
			case "version":
				// rowInput.Version = val
				v, err := strconv.Atoi(val)
				if err == nil && v != 0 {
					rowInput.Version = v
				}
			case "community":
				rowInput.Community = val
			case "oids":
				if val != "" {
					rowInput.Oids = strings.Split(val, " ")
				} else {
					rowInput.Oids = oids
				}
			case "timeout":
				rowInput.Timeout = c.timeout
				t, err := strconv.Atoi(val)
				if err == nil && t != 0 {
					rowInput.Timeout = t
				}
			case "retries":
				rowInput.Retries = c.retries
				t, err := strconv.Atoi(val)
				if err == nil && t != 0 {
					rowInput.Retries = t
				}
			case "port":
				rowInput.Port = c.port
				t, err := strconv.Atoi(val)
				if err == nil && t != 0 {
					rowInput.Port = t
				}
			case "security_level":
				rowInput.SecurityLevel = val
			case "user_name":
				rowInput.UserName = val
			case "auth_type":
				rowInput.AuthType = val
			case "auth_pass":
				rowInput.AuthPass = val
			case "priv_type":
				rowInput.PrivType = val
			case "priv_pass":
				rowInput.PrivPass = val
			case "context_name":
				rowInput.ContextName = val
			case "context_engineid":
				rowInput.ContextEngineID = val
			}
		}
		// re validating the result
		if rowInput.Version == 0 {
			rowInput.Version = 2
		}
		if len(rowInput.Oids) == 0 {
			rowInput.Oids = oids
		}
		// adding as total input
		out = append(out, rowInput)
	}
	return out
}

func (c *_csv) ProduceOutput(ch <-chan Output, exitCh chan<- struct{}) {
	file, err := os.Create(c.ofile)
	if err != nil {
		slog.Error("Unable to write into file", "error", err)
		os.Exit(1)
	}
	defer file.Close()
	file.Write([]byte("ip,tag,result,error\n"))
	for r := range ch {
		// r.Data = []Data{{Value: 12423, Name: "1.2.3.4.5"}, {Value: 12423, Name: "1.234.34.45.4.2.3.243.43.4.53.0", Type: 70}}
		var data []string
		for _, v := range r.Data {
			data = append(data, fmt.Sprintf("%s=%v:%v", v.Name, v.Type, v.Value))
		}
		file.Write([]byte(fmt.Sprintf("%s,%s,%s,%s\n", r.I.IP, r.I.Tag, strings.Join(data, "|"), r.Err)))
	}
	exitCh <- struct{}{}
}

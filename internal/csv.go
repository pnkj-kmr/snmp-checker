package internal

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
)

// InputV2C represent the input for version v2c
type InputV2C struct {
	IP        string
	Community string
}

// InputV3 represent the input for version v3
type InputV3 struct {
	IP       string
	UserName string
	AuthType string
	AuthPass string
	PrivType string
	PrivPass string
}

// Output represent the output result
type Output struct {
	IP     string
	Tag    string
	Result []string
	Err    error
}

// GetIPList helps get IP list from csv
func GetIPList(f string) ([]InputV2C, []InputV3) {
	file, err := os.Open(f)

	if err != nil {
		log.Fatal("Error while reading the file", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatal("Error while Error reading records - ", err)
	}

	var v2c []InputV2C
	var v3 []InputV3
	for _, r := range records {
		if len(r) == 2 {
			v2c = append(v2c, InputV2C{r[0], r[1]})
		} else if len(r) == 6 {
			// TODO - need to revisit in case of SNMP v3
			v3 = append(v3, InputV3{r[0], r[1], r[2], r[3], r[4], r[5]})
		}
	}
	return v2c, v3
}

// PutOutput helps to write result into file
func PutOutput(f string, ch <-chan Output, exit chan<- struct{}) {
	file, err := os.Create(fmt.Sprintf("./%s", f))
	if err != nil {
		log.Fatal("Unable to write into file -", err)
	}
	defer file.Close()
	file.Write([]byte("ip,tag,result,error_if_any\n"))
	for r := range ch {
		// log.Println("-------", r)
		x := strings.Join(r.Result, "|")
		file.Write([]byte(fmt.Sprintf("%s,%s,%s,%s\n", r.IP, r.Tag, x, r.Err.Error())))
	}
	exit <- struct{}{}
}

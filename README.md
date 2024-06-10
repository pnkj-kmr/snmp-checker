# snmp-checker

snmp-checker helps to check SNMP status for multiple IPs with csv input file and generate the output.csv as a result.

### HOW TO USE

_Download the relevent os package from [here](https://github.com/pnkj-kmr/snmp-checker/releases)_

_create a **input.csv** file into your current working directory_

```
# SNMP v2c
ip,community_string
<ip_address1>,<pulic>
<ip_address2>,<abc>
<ip_address3>,<xyz>

...
```

_OR_

```
# SNMP v3
ip,username,auth_type,auth_pass,priv_type,priv_pass
<ip_address1>,user1,MD5,zyx,AES,sdhsd
<ip_address2>,user2,SHA,zyx,AES,sdhsd
<ip_address3>,user1,MD5,zyx,DES,sdhsd

...
```

_After creating the file run the executable binary as_

```
./snmpchecker
```

### OUTPUT

_As a result **output.csv** file will be created after completion_

```
ip,tag,result,error_if_any



```

### HELP

```
./snmpchecker --help

----------------------
Usage of ./snmpchecker:
  -f string
        give a file name (default "input.csv")
  -o string
        output file name (default "output.csv")
  -oid string
        snmp walk oid (multiple -oid 'oid1 oid2 oid3') (default "1.3.6.1.2.1.1.1.0")
  -port int
        snmp port (default 161)
  -r int
        retries
  -t int
        snmp timeout [secs] (default 5)
  -v string
        SNMP version (2c / 3) (default "2c")
  -w int
        number of workers (default 4)

-------
Example:

./snmpchecker -f x.csv -t 30 -w 20

```

## OPTIONS

---

### `-f` (DEFAULT: "./input.csv")

Different input file if any

```
./snmpchecker -f ./new_input_file.csv
```

### `-o` (DEFAULT: "output.csv")

Different output file as

```
./snmpchecker -o new_output.csv
```

### `-oid` (DEFAULT: "1.3.6.1.2.1.1.1.0")

Passing new oid as

```
./snmpchecker -oid 1.3.6.1.2.1.1.3.0
# OR
./snmpchecker -oid "1.3.6.1.2.1.1.2.0 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.1.4.0"
```

### `-port` (DEFAULT: "161")

SNMP port

```
./snmpchecker -port 161
```

### `-w` (DEFAULT: 4)

Increase worker processes if needed

```
./snmpchecker -w 1000
```

### `-t` (DEFAULT: 5 (secs))

Increase end IP SNMP timeout

```
# timeout 10 seconds
./snmpchecker -t 10
```

### `-v` (DEFAULT: 2c)

SNMP version changes

```
./snmpchecker -v 3
```

### `-r` (DEFAULT: 0)

SNMP retries

```
./snmpchecker -r 1
```

:)

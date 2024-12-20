# snmp-checker

snmp-checker helps to get SNMP status for multiple IPs over mutliple oids with csv/json input file and generate the output.csv/json as a result.

### HOW TO USE

_Download the relevent os package from [here](https://github.com/pnkj-kmr/snmp-checker/releases)_

_create a **input.csv** file_

```
ip,tag,version,community,oids,timeout,retries,port,security_level,user_name,auth_type,auth_pass,priv_type,priv_pass,context_name,context_engineid
125.72.255.123,test,3,air,"1.1 2.2 3.3",,0,1611,,user1,MD5,test123,AES,test123,,
127.0.0.1,t0,2,air2,,2,,,,,,,,,,

...
```

_OR_

_create a **input.json** file_

```
[
    { 
      "ip": "125.72.255.123", 
      "tag": "test",				# optional
      "version": 3,					# optional (v2c: 2 | v3: 3) default: v2c
      "community": "air", 			# optional
      "oids": ["1.1", "2.2", "3.3"],# optional
      "timeout": 5,					# optional default: 5
      "retries": 0,					# optional detault: 0
      "port": 1611,					# optional default: 161
      "security_level": "",			# optional (NoAuthNoPriv | AuthNoPriv | AuthPriv | Reportable) default: AuthPriv
      "user_name": "testuser",		# optional
      "auth_type": "MD5",			# optional (MD5|SHA|SHA224|SHA-224|SHA256|SHA-256|SHA384|SHA-384|SHA512|SHA-512)
      "auth_pass": "123",			# optional
      "priv_type": "AES",			# optional (DES|AES|AES-128|AES192|AES-192|AES256|AES-256|
	  											AES192C|AES-192C|AES256C|AES-256C)
      "priv_pass": "123",			# optional
      "context_name": "",			# optional
      "context_engineid": ""		# optional
      "custom_type": ""		      # optional  (MAC|HEXA|STRING)
    },
    { 
      "ip": "127.0.0.1", 
      "community": "test" ,
      "version": 2
    },
	...
]
```

_After creating the file run the executable binary as_

```
./snmpchecker
```

### OUTPUT

_As a result **output.csv** file will be created after completion_

```
ip,tag,result,error



```

_OR_

_As a result **output.csv** file will be created after completion_

```
[
  {
    "input": {
      "ip": "127.0.0.1",
      "version": 2,
      "community": "test",
      "oids": ["1.3.6.1.2.1.1.1.0"],
      "timeout": 5,
      "port": 161
    },
    "error": "error reading from socket: read udp 127.0.0.1:53483-\u003e127.0.0.1:161: recvfrom: connection refused",
    "data": []
  },
  {
    "input": {
      "ip": "125.72.255.123",
      "tag": "test",
      "version": 3,
      "community": "air",
      "oids": ["1.1", "2.2", "3.3"],
      "timeout": 5,
      "port": 1611,
      "user_name": "testuser",
      "auth_type": "MD5",
      "auth_pass": "123",
      "priv_type": "AES",
      "priv_pass": "123"
    },
    "error": "request timeout (after 0 retries)",
    "data": []
  }
  ...
]
```


### HELP

```
./snmpchecker --help

----------------------
Usage of ./snmpchecker:
  -f string
        give a file name (default "input.csv")
  -json
        file type - default[csv]
  -o string
        output file name (default "output.csv")
  -oid string
        snmp walk oid (multiple -oid 'oid1 oid2 oid3') (default "1.3.6.1.2.1.1.1.0")
  -operation string
        for snmp operations GET/WALK/BULKWALK (default "GET")
  -port int
        snmp port (default 161)
  -r int
        retries
  -t int
        snmp timeout [secs] (default 5)
  -v string
        SNMP version (1 / 2c / 3) (default "2c")
  -w int
        number of worker (default 4)

-------
Example:

./snmpchecker -f x.csv -t 30 -w 20

```

## OPTIONS

---

### `-f` (DEFAULT: "input.csv")

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

### `-json` (DEFAULT: csv)

For json input and output

```
./snmpchecker -json
```

### `-operation` (DEFAULT: GET)

To perform complete snmp operation like GET/WALK/BULKWALK 

```
./snmpchecker -operation WALK
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

### data type mapping

```
// Asn1BER's - http://www.ietf.org/rfc/rfc1442.txt

EndOfContents     Asn1BER = 0x00
UnknownType       Asn1BER = 0x00
Boolean           Asn1BER = 0x01
Integer           Asn1BER = 0x02
BitString         Asn1BER = 0x03
OctetString       Asn1BER = 0x04
Null              Asn1BER = 0x05
ObjectIdentifier  Asn1BER = 0x06
ObjectDescription Asn1BER = 0x07
IPAddress         Asn1BER = 0x40
Counter32         Asn1BER = 0x41
Gauge32           Asn1BER = 0x42
TimeTicks         Asn1BER = 0x43
Opaque            Asn1BER = 0x44
NsapAddress       Asn1BER = 0x45
Counter64         Asn1BER = 0x46
Uinteger32        Asn1BER = 0x47
OpaqueFloat       Asn1BER = 0x78
OpaqueDouble      Asn1BER = 0x79
NoSuchObject      Asn1BER = 0x80
NoSuchInstance    Asn1BER = 0x81
EndOfMibView      Asn1BER = 0x82
```


:)

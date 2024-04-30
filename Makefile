b:
	go build -o snmpchecker main.go

r:
	go run main.go

run:
	./snmpchecker -f ./input.csv -w 10

release:
	goreleaser release --snapshot --clean 

build:
	goreleaser build --single-target --snapshot --clean


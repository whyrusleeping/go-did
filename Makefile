
sources := did.go key.go keyutil.go signing.go

didcli: cmd/didcli/main.go $(sources)
	go build -o $@ $<


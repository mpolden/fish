all: fmt lint test

fmt:
	gofmt -tabs=false -tabwidth=4 -w=true *.go

lint:
	go vet *.go
	test -x bin/golint && ./bin/golint *.go

deps:
	go get code.google.com/p/go.crypto/blowfish

deps-dev:
	go get github.com/golang/lint/golint

test:
	go test

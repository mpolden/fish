all: fmt test

fmt:
	gofmt -tabs=false -tabwidth=4 -w=true *.go

deps:
	go get code.google.com/p/go.crypto/blowfish

test:
	go test

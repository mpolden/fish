all: test

fmt:
	gofmt -w=true *.go

deps:
	go get -d

test:
	go test

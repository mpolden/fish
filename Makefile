all: deps test

fmt:
	go fmt

test:
	go test

deps:
	go get -d -v

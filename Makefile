all: linux osx windows

linux: build/linux-amd64/simpleca

osx: build/osx-amd64/simpleca

windows: build/win-amd64/simpleca.exe

build:
	mkdir build

# Linux Build
build/linux-amd64: build
	mkdir build/linux-amd64

build/linux-amd64/simpleca: main.go build/linux-amd64
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o $@ github.com/waucka/simpleca
# OS X Build
build/osx-amd64: build
	mkdir build/osx-amd64

build/osx-amd64/simpleca: main.go build/osx-amd64
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o $@ github.com/waucka/simpleca
# Windows Build
build/win-amd64: build
	mkdir build/win-amd64

build/win-amd64/simpleca.exe: main.go build/win-amd64
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o $@ github.com/waucka/simpleca

clean:
	rm -f build/linux-amd64/simpleca
	rm -f build/osx-amd64/simpleca
	rm -f build/win-amd64/simpleca.exe
	rm -f *~

.PHONY: all clean linux osx windows

all:
	go build -i \
		-gcflags="-N" \
		-gcflags="-nolocalimports" \
		-gcflags="-pack" \
		-gcflags="-trimpath=." \
		-asmflags="-trimpath=." \
		-gcflags="-trimpath=$$GOPATH/src/" \
		-asmflags="-trimpath=$$GOPATH/src/" \
		-ldflags="-s" \
		-o dist/packngo
	cp -r data/ dist/
clean:
	rm -rf dist/;
	go build -i \
		-gcflags="-N" \
		-gcflags="-nolocalimports" \
		-gcflags="-pack" \
		-gcflags="-trimpath=." \
		-asmflags="-trimpath=." \
		-gcflags="-trimpath=$$GOPATH/src/" \
		-asmflags="-trimpath=$$GOPATH/src/" \
		-ldflags="-s" \
		-o dist/packngo;
	cp -r data/ dist/

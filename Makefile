all:
	cp lib/packngo/Obfuscation.go lib/packngo/Obfuscation.go.bak;
	sed -i "s/LAUNCHERSTUB/$$(base64 -w0 data/Launcher.go)/g" lib/packngo/Obfuscation.go;
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
	mv lib/packngo/Obfuscation.go.bak lib/packngo/Obfuscation.go
clean:
	rm -rf dist/;
	cp lib/packngo/Obfuscation.go lib/packngo/Obfuscation.go.bak;
	sed -i "s/LAUNCHERSTUB/$$(base64 -w0 data/Launcher.go)/g" lib/packngo/Obfuscation.go;
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
	mv lib/packngo/Obfuscation.go.bak lib/packngo/Obfuscation.go;

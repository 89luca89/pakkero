all:
	cp lib/pakkero/Obfuscation.go lib/pakkero/Obfuscation.go.bak;
	sed -i "s|LAUNCHERSTUB|$$(base64 -w0 data/Launcher.go)|g" lib/pakkero/Obfuscation.go;
	go build -i \
		-gcflags="-N" \
		-gcflags="-nolocalimports" \
		-gcflags="-pack" \
		-gcflags="-trimpath=." \
		-asmflags="-trimpath=." \
		-gcflags="-trimpath=$$GOPATH/src/" \
		-asmflags="-trimpath=$$GOPATH/src/" \
		-ldflags="-s" \
		-o dist/pakkero; mv lib/pakkero/Obfuscation.go.bak lib/pakkero/Obfuscation.go
	strip \
		-sxX \
		--remove-section=.bss \
		--remove-section=.comment \
		--remove-section=.eh_frame \
		--remove-section=.eh_frame_hdr \
		--remove-section=.fini \
		--remove-section=.fini_array \
		--remove-section=.gnu.build.attributes \
		--remove-section=.gnu.hash \
		--remove-section=.gnu.version \
		--remove-section=.got \
		--remove-section=.note.ABI-tag \
		--remove-section=.note.gnu.build-id \
		--remove-section=.note.go.buildid \
		--remove-section=.shstrtab \
		--remove-section=.typelink \
		dist/pakkero;
clean:
	rm -rf dist/;
	cp lib/pakkero/Obfuscation.go lib/pakkero/Obfuscation.go.bak;
	sed -i "s|LAUNCHERSTUB|$$(base64 -w0 data/Launcher.go)|g" lib/pakkero/Obfuscation.go;
	go build -i \
		-gcflags="-N" \
		-gcflags="-nolocalimports" \
		-gcflags="-pack" \
		-gcflags="-trimpath=." \
		-asmflags="-trimpath=." \
		-gcflags="-trimpath=$$GOPATH/src/" \
		-asmflags="-trimpath=$$GOPATH/src/" \
		-ldflags="-s" \
		-o dist/pakkero; mv lib/pakkero/Obfuscation.go.bak lib/pakkero/Obfuscation.go
	strip \
		-sxXwSgd \
		--remove-section=.bss \
		--remove-section=.comment \
		--remove-section=.eh_frame \
		--remove-section=.eh_frame_hdr \
		--remove-section=.fini \
		--remove-section=.fini_array \
		--remove-section=.gnu.build.attributes \
		--remove-section=.gnu.hash \
		--remove-section=.gnu.version \
		--remove-section=.got \
		--remove-section=.note.ABI-tag \
		--remove-section=.note.gnu.build-id \
		--remove-section=.note.go.buildid \
		--remove-section=.shstrtab \
		--remove-section=.typelink \
		dist/pakkero

test: clean
	dist/pakkero \
		--file /usr/bin/echo \
		-o /tmp/test.enc \
		-offset 2850000 \
		-register-dep /usr/bin/bash;
	sync;
	for i in $$(seq 1 20); do /tmp/test.enc $$i; done;
	test_enc

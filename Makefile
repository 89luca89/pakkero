all:
	go build -i \
		-gcflags="-N" \
		-gcflags="-nolocalimports" \
		-gcflags="-pack" \
		-gcflags="-trimpath=." \
		-asmflags="-trimpath=." \
		-gcflags="-trimpath=$$GOPATH/src/" \
		-asmflags="-trimpath=$$GOPATH/src/" \
		-ldflags="-X github.com/89luca89/pakkero/internal/pakkero.LauncherStub=$$(base64 -w0 data/launcher.go) -s" \
		-o dist/pakkero;
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
		--remove-section=.shstrtab \
		--remove-section=.typelink \
		dist/pakkero;
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
		-ldflags="-X github.com/89luca89/pakkero/internal/pakkero.LauncherStub=$$(base64 -w0 data/launcher.go) -s" \
		-o dist/pakkero;
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
		--remove-section=.shstrtab \
		--remove-section=.typelink \
		dist/pakkero

test: clean
	dist/pakkero \
		-file /usr/bin/echo -c \
		-o /tmp/test.enc \
		-offset 2850000 \
		-enable-stdout \
		-register-dep /usr/bin/bash;
	sync;
	sh -c "/tmp/test.enc test"

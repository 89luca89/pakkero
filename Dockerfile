FROM golang:alpine

ENV CGO_ENABLED=0
ENV GO111MODULE=off

RUN apk add --update-cache upx git make binutils coreutils \
    && rm -rf /var/cache/apk/*

RUN upx --version

RUN go version
RUN go get -d -v github.com/89luca89/pakkero

WORKDIR $GOPATH/src/github.com/89luca89/pakkero
RUN make

RUN ./dist/pakkero -v

ENTRYPOINT ["./dist/pakkero"]
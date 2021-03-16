FROM amd64/golang:latest

ENV CGO_ENABLED=0
ENV GO111MODULE=off

RUN apt-get update \
    && apt-get install -y \
    && apt-get install -y upx \ 
    && rm -rf /var/lib/apt/lists/*

RUN upx --version

RUN go version
RUN go get -d -v github.com/89luca89/pakkero

WORKDIR $GOPATH/src/github.com/89luca89/pakkero
RUN make

RUN ./dist/pakkero -v

ENTRYPOINT ["./dist/pakkero"]

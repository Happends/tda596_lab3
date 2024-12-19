

FROM golang:1.23 AS build


ARG IP="127.0.0.1"
ARG PORT="2000"
ARG JIP="-1"
ARG JPORT="-1"


RUN apt-get update
RUN apt install bash -y
RUN apt install git -y
RUN apt install gcc -y
RUN apt install musl-dev -y

RUN export PATH="$PATH:$(go env GOPATH)/bin"

RUN apt install protobuf-compiler -y
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest


WORKDIR /app 

COPY ca.crt ca.key ca.srl chord.go chordFileTransfer.proto client_signed.crt client.csr client.key go.mod go.sum keygen.sh openssl.cnf server_signed.crt server.csr server.key .

RUN echo $(ls -1 .)

RUN mkdir chordFileTransfer

RUN protoc --go_out=chordFileTransfer --go_opt=paths=source_relative --go-grpc_out=chordFileTransfer --go-grpc_opt=paths=source_relative chordFileTransfer.proto

RUN echo $(ls ./chordFileTransfer)

RUN echo "$IP $PORT $JIP $JPORT"

ENV IP=${IP}
ENV PORT=${PORT}
ENV JIP=${JIP}
ENV JPORT=${JPORT}


EXPOSE ${PORT}

RUN echo "$IP $PORT $JIP $JPORT"

CMD "go" "run" "chord.go" "-a" "$IP" "-p" "$PORT" "--ja" "$JIP" "--jp" "$JPORT" "-d" "1"
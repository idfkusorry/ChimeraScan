FROM golang:1.24-alpine

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./

RUN go build -o /nuclei-scanner

RUN apk add --no-cache git

ENTRYPOINT ["/nuclei-scanner"]
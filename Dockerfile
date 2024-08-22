# syntax=docker/dockerfile:1

FROM golang:1.19-alpine
WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download
COPY . .

RUN go build -o ./qaim-be

EXPOSE 443
EXPOSE 8080

ENTRYPOINT ["/app/qaim-be"]
FROM golang:1.21

RUN go version
ENV GOPATH=/

COPY ./ ./

RUN apt-get update

# Install PostgreSQL client
RUN apt-get -y install postgresql-client

# build go app
RUN go mod download
RUN go build -o auth-service ./cmd/main.go

CMD ["./auth-service"]
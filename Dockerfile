FROM golang:1.22 AS build

WORKDIR /var/www

COPY ["go.mod", "go.sum", "./"]
RUN go mod download -x
COPY . .
RUN go build -o /tmp/external-dns-custom

FROM gcr.io/distroless/static-debian11:latest as dist

COPY --from=build /tmp/external-dns-custom /bns-app/external-dns-custom

ENTRYPOINT ["/bns-app/external-dns-custom"]

FROM golang:1.24 AS build
COPY ./docker-gitconfig /root/.gitconfig
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/security-hub-collector .

FROM alpine:3.22 AS certs
RUN apk --no-cache add ca-certificates

FROM scratch
COPY --from=build /bin/security-hub-collector /bin/security-hub-collector
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/bin/security-hub-collector"]

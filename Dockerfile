FROM golang:1.21 as build
COPY ./docker-gitconfig /root/.gitconfig
COPY . /build
RUN cd /build; CGO_ENABLED=0 GOBIN=/bin/ go install .

FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM scratch
COPY --from=build /bin/security-hub-collector /bin/security-hub-collector
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/bin/security-hub-collector"]

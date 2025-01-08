FROM golang:1.21 as build
COPY ./docker-gitconfig /root/.gitconfig
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 GOBIN=/bin/ go install .

FROM alpine:3.21 as certs
RUN apk --no-cache add ca-certificates=20241121-r1

FROM scratch
COPY --from=build /bin/security-hub-collector /bin/security-hub-collector
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/bin/security-hub-collector"]

FROM alpine:3
COPY dist/security-hub-collector_linux_amd64/security-hub-collector /bin/security-hub-collector
ENTRYPOINT [ "security-hub-collector" ]

FROM alpine:3
COPY dist/security-hub-collector_linux_amd64/security-hub-collector /bin/security-hub-collector
COPY scriptRunner.sh scriptRunner.sh
ENTRYPOINT [ "security-hub-collector" ]
FROM alpine:3
COPY security-hub-collector /bin/security-hub-collector
ENTRYPOINT [ "security-hub-collector" ]

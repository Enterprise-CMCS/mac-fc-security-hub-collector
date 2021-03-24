FROM alpine:3
COPY my-cli-tool /bin/my-cli-tool
ENTRYPOINT [ "my-cli-tool" ]

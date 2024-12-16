FROM golang:1.21-alpine
RUN apk add --no-cache bash git
COPY ./docker-gitconfig /root/.gitconfig
COPY . /build
RUN cd /build; CGO_ENABLED=0 GOBIN=/bin/ go install .
ENTRYPOINT ["/bin/security-hub-collector"]

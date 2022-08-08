FROM golang:1.19.0-alpine3.16
RUN apk add --no-cache bash
COPY . /build
RUN cd /build; CGO_ENABLED=0 GOBIN=/bin/ go install .
COPY scriptRunner.sh scriptRunner.sh
ENTRYPOINT ["./scriptRunner.sh"]

FROM golang:1.19-alpine
RUN apk add --no-cache bash=5.2.15-r5
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 GOBIN=/bin/ go install .
WORKDIR /app
COPY scriptRunner.sh .
ENTRYPOINT ["./scriptRunner.sh"]

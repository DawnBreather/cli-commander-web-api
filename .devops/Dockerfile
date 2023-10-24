FROM golang:alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY . .
# RUN GOOS=linux GOARCH=amd64 go test ./...
RUN GOOS=linux GOARCH=amd64 go build -o /out/cli_commander_web_api main/main.go

FROM debian
ENV CLI_COMMANDER_AUTH_TOKEN = ""
ENV CLI_COMMANDER_SOCKET = ""

COPY --from=build /out/cli_commander_web_api /usr/bin

CMD /usr/bin/cli_commander_web_api
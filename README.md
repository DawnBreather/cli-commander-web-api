#CLI Commander Web Server
The CLI Commander Web Server is a Golang-based server designed to execute CLI commands that are sent via HTTP requests. It emphasizes security, allowing requests only from localhost and requiring a token-based authentication.

## Features
* **Localhost Restriction:** Ensures that all requests originate from the localhost.
* **Token-based Authorization:** Uses a bearer token for authentication.
* **Base64 Encoding:** Command input is expected to be base64 encoded for an added layer of obfuscation.

## Setup
1. Clone the repository:

```shell
git clone [YOUR REPOSITORY URL]
```

2. Navigate to the project directory:
```shell
cd [YOUR PROJECT DIRECTORY]
```

3. Build the server:

```shell
go build -o server
```

## Configuration
You can configure the server using both environment variables and CLI flags.

### Environment Variables:

* **CLI_COMMANDER_SOCKET:** Specifies the listening address and port (default: 127.0.0.1:8080).
* **CLI_COMMANDER_AUTH_TOKEN:** The authorization token required to make requests to the server.

### CLI Flags:

* **--socket:** Specifies the listening address and port, overriding the CLI_COMMANDER_SOCKET environment variable if set.
* --auth-token: Specifies the authorization token, overriding the CLI_COMMANDER_AUTH_TOKEN environment variable if set.

## Running the Server
### Using environment variables:
```shell
export CLI_COMMANDER_SOCKET=":8081"
export CLI_COMMANDER_AUTH_TOKEN="your_secret_token"
./server
```

### Using CLI flags:
```shell
./server --socket ":8081" --auth-token "your_secret_token"
# Remember: CLI flags will override the corresponding environment variables if both are set.
```

## Usage
To execute a command, make a POST request to the `/execute` endpoint with your command base64 encoded in the body and the authorization token in the header.

For example:
1) Example 1
```shell
echo -n "ls -la" | base64
# This will produce: bHMgLWxh

curl -X POST \
-H "Authorization: Bearer your_secret_token" \
-d "bHMgLWxh" \
http://localhost:8081/execute
```

2) Example 2
```shell
echo -n "ls -la" | base64 | curl -X POST -H "Content-Type: text/plain" -H "Authorization: Bearer token_here" --data-binary @- http://localhost:8081/execute
```

## Security
Always be cautious when executing remote commands, especially on production servers. Ensure your token is kept secret and change it regularly.
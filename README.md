# Double-Blind Email Project

A web application with a server component and command-line client.

## Project Structure

- `server/` - Server component
  - `src/server.js` - Express.js server implementation
  - `package.json` - Server dependencies and scripts

- `client/` - Command-line client
  - `src/cli.js` - CLI implementation
  - `package.json` - Client dependencies and scripts
  - Uses snarkjs for zero-knowledge proof generation

## Dependencies

### Server Dependencies
- Express.js for the web server
- Other dependencies listed in server/package.json

### Client Dependencies
- Commander.js for CLI argument parsing
- Axios for HTTP requests
- Snarkjs for zero-knowledge proof generation
- Other dependencies listed in client/package.json

## Setup

1. Install server dependencies:
```bash
cd server
npm install
```

2. Install client dependencies:
```bash
cd client
npm install
```

## Running the Application

1. Start the server:
```bash
cd server
npm start
```

2. Use the client (in a separate terminal):
```bash
cd client
npm start -- -f <filename> -m <message>
```

## CLI Usage

The client supports the following options:
- `-f, --file <filename>` - Specify a filename
- `-m, --message <message>` - Specify a message string
- `-s, --server <url>` - Specify server URL (default: http://localhost:3000) 
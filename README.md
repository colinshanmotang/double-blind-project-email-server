# Node.js Web Application with CLI

A simple web application with a local server and command-line interface for testing.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
node src/server.js
```

3. Use the CLI:
```bash
node src/cli.js -f <filename> -m <message>
```

## Project Structure

- `src/server.js` - Express.js server implementation
- `src/cli.js` - Command-line interface
- `src/routes/` - Server route handlers
- `src/utils/` - Utility functions

## CLI Usage

The CLI supports the following options:
- `-f, --file <filename>` - Specify a filename
- `-m, --message <message>` - Specify a message string 
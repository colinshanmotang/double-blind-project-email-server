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

## Required files

You will need to download the file `client/public/rsa_0001.zkey` from [here](https://drive.google.com/file/d/1TLXSpmupKv_3dLAzZM2kYWmi7ZeRq5w8/view?usp=sharing) since it is 700 MB and thus too large for github.

You will also need to make sure your username/public key are in `client/public/public-key-directory.txt`.

Then you can just run the CLI client using the instructions above. Try running `npm start -- -f ~/.ssh/id_rsa -m "hello world" -g gubsheep,ndwrobotics,colinshanmotang,[insert username here]`

Currently the server lives on my laptop, so the functionality will only work when my laptop is running :P

TODO: Replace `localhost:3000` with something that actually would work on a machine that is not the server

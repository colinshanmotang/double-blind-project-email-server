const { program } = require('commander');
const axios = require('axios');

// Configure command-line options
program
    .option('-f, --file <filename>', 'Specify a filename')
    .option('-m, --message <message>', 'Specify a message string')
    .parse(process.argv);

const options = program.opts();

// Validate required options
if (!options.file || !options.message) {
    console.error('Error: Both filename (-f) and message (-m) are required');
    process.exit(1);
}

// Send request to server
async function sendRequest() {
    try {
        const response = await axios.post('http://localhost:3000/test', {
            filename: options.file,
            message: options.message
        });
        console.log('Server response:', response.data);
    } catch (error) {
        console.error('Error sending request:', error.message);
        process.exit(1);
    }
}

sendRequest(); 
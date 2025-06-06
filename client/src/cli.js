import { program } from 'commander';
import axios from 'axios';
import { spawn } from 'child_process';
import { writeFileSync, unlinkSync, readFileSync } from 'fs';
import * as snarkjs from '../lib/snarkjs.min.js';
import * as SignatureProcessing from '../lib/signature-processing.js';


// Generate SSH signature
async function generateSignature(message, keyFile) {
    return new Promise((resolve, reject) => {
        try {
            console.log("Entering generateSignature");
            // Create a temporary file for the message
            const tempFile = 'temp_message.txt';
            writeFileSync(tempFile, message);

            // Spawn ssh-keygen process with stdio configuration
            const sshKeygen = spawn('ssh-keygen', [
                '-Y', 'sign',
                '-f', keyFile,
                '-n', 'file',
                tempFile
            ], {
                stdio: ['inherit', 'inherit', 'inherit'] // This ensures stdin is inherited from parent process
            });

            // Handle process completion
            sshKeygen.on('close', (code) => {
                // Clean up temporary file
                unlinkSync(tempFile);

                if (code !== 0) {
                    console.error('Error during signature generation:', stderrData);
                    reject(new Error('Signature generation failed'));
                    return;
                }

                try {
                    // Read the signature file
                    const signatureFile = `${tempFile}.sig`;
                    const signature = readFileSync(signatureFile, 'utf8');
                    console.log("Signature:", signature);
                    // Clean up signature file
                    unlinkSync(signatureFile);

                    resolve(signature);
                } catch (error) {
                    reject(new Error(`Failed to read signature file: ${error.message}`));
                }
            });

            // Handle errors
            sshKeygen.on('error', (error) => {
                console.error('Error spawning ssh-keygen:', error);
                reject(error);
            });

        } catch (error) {
            console.error('Error in signature generation:', error.message);
            reject(error);
        }
    });
}

// Send request to server
async function sendRequest() {
    try {

        
        const response = await axios.post('http://localhost:3000/test', {
            filename: options.file,
            message: options.message,
            signature: signature
        });
        console.log('Server response:', response.data);
    } catch (error) {
        console.error('Error sending request:', error.message);
        process.exit(1);
    }
}


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

// Generate signature
const signature = await generateSignature(options.message, options.file);
const signature_info = SignatureProcessing.parseRSA_SHA2_512Signature(signature);
console.log("Signature info:", signature_info);
//sendRequest(); 
import { program } from 'commander';
import axios from 'axios';
import { spawn } from 'child_process';
import { writeFileSync, unlinkSync, readFileSync } from 'fs';
import * as snarkjs from 'snarkjs';
import * as SignatureProcessing from '../lib/signature-processing.js';
import { createInterface } from 'readline/promises';




const BITS_PER_REGISTER = 121n;
const REGISTERS_PER_INT = 34;
const NAMESPACE = "kudosBot";
const KEY_LENGTH_BYTES = 512;

function readPublicKeys() {
    const publicKeyText = readFileSync('public/public-key-directory.txt', 'utf8');
    const keyTextList = publicKeyText.split('\n');
    const publicKeys = new Map();
    for (const keyText of keyTextList) {
        const [username, ...keyParts] = keyText.trim().split(' ');
        if (username === '') {
            continue;
        }
        const key = keyParts.join(' ');
        publicKeys.set(username, key);
    }
    return publicKeys;
}

function bigint_to_registers(n, k, bi) {
    //k registers, of size n each
    //little-endian
    let result = [];
    let bi_temp = bi;
    for(let i =0; i < k; i++){
        result.push((bi_temp % (1n << n)).toString());
        bi_temp = bi_temp / (1n << n);
    }
    return result;
}

// Generate SSH signature
async function generateSignature(message, keyFile) {
    return new Promise((resolve, reject) => {
        try {
            // Create a temporary file for the message
            const tempFile = 'temp_message.txt';
            writeFileSync(tempFile, message);

            // Spawn ssh-keygen process with stdio configuration
            const sshKeygen = spawn('ssh-keygen', [
                '-Y', 'sign',
                '-f', keyFile,
                '-n', NAMESPACE,
                tempFile
            ], {
                stdio: ['inherit', 'inherit', 'inherit'] // This ensures stdin is inherited from parent process
            });

            // Handle process completion
            sshKeygen.on('close', (code) => {
                // Clean up temporary file
                unlinkSync(tempFile);

                if (code !== 0) {
                    reject(new Error('Signature generation failed'));
                    return;
                }

                try {
                    // Read the signature file
                    const signatureFile = `${tempFile}.sig`;
                    const signature = readFileSync(signatureFile, 'utf8');

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
async function sendRequest(options, proofResults) {
    try {

        
        const response = await axios.post('http://localhost:3000/sendMessage', {
            message: options.message,
            groupMembers: options.groupMembers,
            proof: proofResults.proof,
            publicInputs: proofResults.publicInputs
        });
        console.log('Server response:', response.data);
    } catch (error) {
        console.error('Error sending request:', error.message);
        process.exit(1);
    }
}

async function generateProof(message, groupMembersPublicKeys, signature) {
    const signatureInfo = SignatureProcessing.parseRSA_SHA2_512Signature(signature);
    function parsePublicKey(key) {
        const publicKeyInfo = SignatureProcessing.parseRSA_SHA2_512PublicKey(key);
        if (publicKeyInfo.modulusLength !== KEY_LENGTH_BYTES) {
            throw new Error(`Public key length mismatch: ${publicKeyInfo.modulusLength} != ${KEY_LENGTH_BYTES}`);
        }
        return publicKeyInfo;
    }
    const publicKeyInfo = groupMembersPublicKeys.map(key => SignatureProcessing.parseSSHRSAPublicKey(key));
    let publicKeyRegisters = publicKeyInfo.map(info => bigint_to_registers(BITS_PER_REGISTER,REGISTERS_PER_INT,info.modulusBigInt));
    
    const zeroRegister = Array(REGISTERS_PER_INT).fill("0");
    for (let i = publicKeyRegisters.length; i < 10; i++){
        publicKeyRegisters.push(zeroRegister);
    }

    const inputJson = {
        "msg":bigint_to_registers(BITS_PER_REGISTER,REGISTERS_PER_INT,SignatureProcessing.generatePKCS1BigInt(message, NAMESPACE, "SHA-512", signatureInfo.modulusLength)),
        "key":bigint_to_registers(BITS_PER_REGISTER,REGISTERS_PER_INT,signatureInfo.modulusBigInt),
        "sig":bigint_to_registers(BITS_PER_REGISTER,REGISTERS_PER_INT,signatureInfo.signatureBigInt),
        "keylist":publicKeyRegisters
    }

    //console.log("Input JSON:", inputJson);
    try {
        const {proof, publicSignals} = await snarkjs.groth16.fullProve(inputJson, "public/rsa-test.wasm", "public/rsa-test_0001.zkey");
        return {proof: proof, publicInputs: publicSignals};
    } catch (error) {
        console.error('Error during proof generation. Did you include yourself in list of group members?');
        console.error(error.message);
        process.exit(1);
    }
}


// Configure command-line options
program
    .option('-f, --file <filename>', 'Specify a filename')
    .option('-m, --message <message>', 'Specify a message string')
    .option('-g, --groupMembers <groupMembers>', 'Specify a list of sender group members (comma-separated, no spaces)')
    .parse(process.argv);

const options = program.opts();

async function main(options) {

    // Validate required options
    if (!options.file || !options.message || !options.groupMembers) {
        console.error('Error: filename (-f), message (-m), and groupMembers (-g) are required');
        process.exit(1);
    }

    const publicKeys = readPublicKeys();
    //console.log("Public keys:", publicKeys);

    // IMPORTANT sort the group members to ensure that the ordering
    // doesn't reveal any information
    const groupMembers = options.groupMembers.split(',').sort();
    const groupMembersPublicKeys = groupMembers.map(member => {
        
        const result = publicKeys.get(member);
        if (result === undefined) {
            console.error(`Error: Public key for ${member} not found`);
            process.exit(1);
        }
        return result;
    });


    let signature;
    // Generate signature
    try {
        signature = await generateSignature(options.message, options.file);
    } catch (error) {
        console.error('Error during signature generation:', error.message);
        process.exit(1);
    }

    const rl = createInterface({
        input: process.stdin,
        output: process.stdout
    });
    console.log("About to send the following message:");
    console.log("--------------------------------");
    console.log("FROM: ", options.groupMembers);
    console.log(options.message);
    console.log("--------------------------------");
    console.log("ATTENTION: Please verify that the message and the senders are correct.");

    const input = await rl.question('Continue? (y/n) ');
    rl.close();
    if (input !== "y" && input !== "Y") {
        console.log("Aborting...");
        process.exit(0);
    }
    console.log("Generating proof... (this may take a while)");
    



    const proofResults = await generateProof(options.message, groupMembersPublicKeys, signature);
    //console.log("Proof results:", proofResults);
    console.log("Proof generated successfully.");
    const tempFile = 'temp_proof.json';
    try {
        writeFileSync(tempFile, JSON.stringify(proofResults));
        await sendRequest(options, proofResults);
    } finally {
        // Clean up temporary file
        try {
            unlinkSync(tempFile);
            process.exit(0);
        } catch (error) {
            console.error('Warning: Failed to clean up temporary file:', error.message);
            process.exit(1);
        }
    }
}




main(options);
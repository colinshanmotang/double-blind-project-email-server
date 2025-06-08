import { program } from 'commander';
import axios from 'axios';
import { spawn } from 'child_process';
import { writeFileSync, unlinkSync, readFileSync } from 'fs';
import * as snarkjs from 'snarkjs';
import * as SignatureProcessing from '../lib/signature-processing.js';

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
                    console.log("Signature:");
                    console.log(signature);
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
    const {proof, publicSignals} = await snarkjs.groth16.fullProve(inputJson, "public/rsa-test.wasm", "public/rsa-test_0001.zkey");
    console.log("Public inputs:", publicSignals);
    return {proof: proof, publicInputs: publicSignals};
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

    const groupMembers = options.groupMembers.split(',');
    const groupMembersPublicKeys = groupMembers.map(member => publicKeys.get(member));


    let signature;
    // Generate signature
    try {
        signature = await generateSignature(options.message, options.file);
    } catch (error) {
        console.error('Error during signature generation:', error.message);
        process.exit(1);
    }

    const proofResults = await generateProof(options.message, groupMembersPublicKeys, signature);
    console.log("Proof results:", proofResults);
    const tempFile = 'temp_proof.json';
    writeFileSync(tempFile, JSON.stringify(proofResults));
}




main(options);
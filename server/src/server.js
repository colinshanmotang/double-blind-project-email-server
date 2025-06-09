//const { google } = require('googleapis');
import { google } from 'googleapis';
import fs from 'fs';
//const path = require('path');
import path from 'path';
import express from 'express';

//const nodemailer = require('nodemailer');
import * as snarkjs from 'snarkjs';
import * as SignatureProcessing from '../signature-processing.js';

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));


// Configuration
const CREDENTIALS_PATH = path.join(process.cwd(), 'credentials.json');
const TOKEN_PATH = path.join(process.cwd(), 'token.json');
const SCOPES = [
    //'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    //'https://www.googleapis.com/auth/gmail.compose'
];

let oauth2Client;

/**
 * Load client secrets from a local file.
 */
async function loadCredentials() {
    try {
        const content = await fs.promises.readFile(CREDENTIALS_PATH);
        const credentials = JSON.parse(content);
        return credentials;
    } catch (error) {
        throw new Error(`Error loading credentials file: ${error.message}`);
    }
}

/**
 * Create an OAuth2 client with the given credentials
 */
async function createOAuth2Client() {
    const credentials = await loadCredentials();
    const { client_secret, client_id, redirect_uris } = credentials.installed || credentials.web;
    
    oauth2Client = new google.auth.OAuth2(
        client_id,
        client_secret,
        redirect_uris[0] || 'http://localhost:3000/auth/callback'
    );
    
    return oauth2Client;
}

/**
 * Check if we have previously stored a token.
 */
async function loadSavedToken() {
    try {
        const token = await fs.promises.readFile(TOKEN_PATH);
        oauth2Client.setCredentials(JSON.parse(token));
        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Save the token to disk for later program executions.
 */
async function saveToken(tokens) {
    await fs.promises.writeFile(TOKEN_PATH, JSON.stringify(tokens));
    console.log('Token stored to', TOKEN_PATH);
}

/**
 * Start the authentication flow
 */
app.get('/auth', async (req, res) => {
    try {
        await createOAuth2Client();
        
        // Check if we already have a token
        const hasToken = await loadSavedToken();
        /*
        if (hasToken) {
            return res.json({ 
                message: 'Already authenticated!',
                redirect: '/test-gmail'
            });
        }
            */
        
        // Generate the url that will be used for the consent dialog
        const authorizeUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: SCOPES,
            prompt: 'consent' // Forces consent screen to get refresh token
        });
        
        console.log('Authorize this app by visiting this url:', authorizeUrl);
        res.redirect(authorizeUrl);
        
    } catch (error) {
        console.error('Error starting auth flow:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Handle the OAuth callback
 */
app.get('/auth/callback', async (req, res) => {
    const { code, error } = req.query;
    
    if (error) {
        return res.status(400).json({ error: `Authorization failed: ${error}` });
    }
    
    if (!code) {
        return res.status(400).json({ error: 'No authorization code received' });
    }
    
    try {
        // Exchange authorization code for tokens
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        
        // Save tokens for future use
        await saveToken(tokens);
        
        console.log('Authentication successful!');
        console.log('Access Token:', tokens.access_token ? 'Present' : 'Missing');
        console.log('Refresh Token:', tokens.refresh_token ? 'Present' : 'Missing');
        
        res.json({
            message: 'Authentication successful!',
            hasAccessToken: !!tokens.access_token,
            hasRefreshToken: !!tokens.refresh_token,
            expiryDate: tokens.expiry_date
        });
        
    } catch (error) {
        console.error('Error during OAuth callback:', error);
        res.status(500).json({ error: `Token exchange failed: ${error.message}` });
    }
});

/**
 * Test Gmail API access
 */
app.get('/test-gmail', async (req, res) => {
    try {
        if (!oauth2Client) {
            await createOAuth2Client();
            const hasToken = await loadSavedToken();
            
            if (!hasToken) {
                return res.status(401).json({ 
                    error: 'Not authenticated. Visit /auth first.' 
                });
            }
        }
        
        // Create Gmail API client
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        
        // Test API call - get user profile
        const profile = await gmail.users.getProfile({ userId: 'me' });
        
        res.json({
            message: 'Gmail API access successful!',
            profile: {
                emailAddress: profile.data.emailAddress,
                messagesTotal: profile.data.messagesTotal,
                threadsTotal: profile.data.threadsTotal
            }
        });
        
    } catch (error) {
        console.error('Gmail API error:', error);
        
        if (error.code === 401) {
            // Token might be expired
            res.status(401).json({ 
                error: 'Authentication expired. Please re-authenticate.',
                redirect: '/auth'
            });
        } else {
            res.status(500).json({ error: error.message });
        }
    }
});

/**
 * Get Gmail messages
 */
app.get('/gmail/messages', async (req, res) => {
    try {
        if (!oauth2Client) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        
        // Get list of messages
        const messages = await gmail.users.messages.list({
            userId: 'me',
            maxResults: 10
        });
        
        res.json({
            messages: messages.data.messages || [],
            resultSizeEstimate: messages.data.resultSizeEstimate
        });
        
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Helper function to create email message
 */
function createEmailMessage(to, subject, body, from) {
    const emailLines = [];
    emailLines.push(`To: ${to}`);
    emailLines.push(`Subject: ${subject}`);
    if (from) {
        emailLines.push(`From: ${from}`);
    }
    emailLines.push('Content-Type: text/html; charset=utf-8');
    emailLines.push('');
    emailLines.push(body);
    
    const email = emailLines.join('\r\n');
    
    // Encode the email in base64url format
    const encodedEmail = Buffer.from(email)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    
    return encodedEmail;
}

/**
 * Send email endpoint
 */
app.post('/gmail/send', async (req, res) => {
    try {
        if (!oauth2Client || !oauth2Client.credentials.access_token) {
            return res.status(401).json({ 
                error: 'Not authenticated. Visit /auth first.' 
            });
        }
        
        const { to, subject, body, from } = req.body;
        
        // Validate required fields
        if (!to || !subject || !body) {
            return res.status(400).json({ 
                error: 'Missing required fields: to, subject, body' 
            });
        }
        
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        
        // Create the email message
        const encodedMessage = createEmailMessage(to, subject, body, from);
        
        // Send the email
        const result = await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: encodedMessage
            }
        });
        
        console.log('Email sent successfully:', result.data.id);
        
        res.json({
            success: true,
            messageId: result.data.id,
            threadId: result.data.threadId,
            message: 'Email sent successfully!'
        });
        
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ 
            error: 'Failed to send email',
            details: error.message 
        });
    }
});

/**
 * Send email with attachments
 */
app.post('/gmail/send-with-attachment', async (req, res) => {
    try {
        if (!oauth2Client || !oauth2Client.credentials.access_token) {
            return res.status(401).json({ 
                error: 'Not authenticated. Visit /auth first.' 
            });
        }
        
        const { to, subject, body, from, attachments } = req.body;
        
        if (!to || !subject || !body) {
            return res.status(400).json({ 
                error: 'Missing required fields: to, subject, body' 
            });
        }
        
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        
        // Create multipart email with attachments
        const boundary = 'boundary_' + Math.random().toString(36).substr(2, 9);
        
        let emailContent = [];
        emailContent.push(`To: ${to}`);
        emailContent.push(`Subject: ${subject}`);
        if (from) {
            emailContent.push(`From: ${from}`);
        }
        emailContent.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
        emailContent.push('');
        emailContent.push(`--${boundary}`);
        emailContent.push('Content-Type: text/html; charset=utf-8');
        emailContent.push('');
        emailContent.push(body);
        
        // Add attachments if provided
        if (attachments && Array.isArray(attachments)) {
            for (const attachment of attachments) {
                emailContent.push(`--${boundary}`);
                emailContent.push(`Content-Type: ${attachment.mimeType || 'application/octet-stream'}`);
                emailContent.push(`Content-Disposition: attachment; filename="${attachment.filename}"`);
                emailContent.push('Content-Transfer-Encoding: base64');
                emailContent.push('');
                emailContent.push(attachment.data); // Should be base64 encoded
            }
        }
        
        emailContent.push(`--${boundary}--`);
        
        const email = emailContent.join('\r\n');
        const encodedEmail = Buffer.from(email)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        
        const result = await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: encodedEmail
            }
        });
        
        res.json({
            success: true,
            messageId: result.data.id,
            threadId: result.data.threadId,
            message: 'Email with attachments sent successfully!'
        });
        
    } catch (error) {
        console.error('Error sending email with attachments:', error);
        res.status(500).json({ 
            error: 'Failed to send email with attachments',
            details: error.message 
        });
    }
});

/**
 * Send HTML email template
 */
app.post('/gmail/send-template', async (req, res) => {
    try {
        if (!oauth2Client || !oauth2Client.credentials.access_token) {
            return res.status(401).json({ 
                error: 'Not authenticated. Visit /auth first.' 
            });
        }
        
        const { to, subject, templateData, from } = req.body;
        
        if (!to || !subject || !templateData) {
            return res.status(400).json({ 
                error: 'Missing required fields: to, subject, templateData' 
            });
        }
        
        // Create HTML email template
        const htmlBody = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #f4f4f4; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .footer { background-color: #f4f4f4; padding: 10px; text-align: center; font-size: 12px; }
                .button { 
                    display: inline-block; 
                    padding: 10px 20px; 
                    background-color: #007cba; 
                    color: white; 
                    text-decoration: none; 
                    border-radius: 5px; 
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>${templateData.title || 'Email from Gmail API'}</h1>
                </div>
                <div class="content">
                    <p>Hello ${templateData.name || 'there'},</p>
                    <p>${templateData.message || 'This is a test email sent via Gmail API.'}</p>
                    ${templateData.buttonText && templateData.buttonUrl ? 
                        `<p><a href="${templateData.buttonUrl}" class="button">${templateData.buttonText}</a></p>` : ''}
                    <p>Best regards,<br>${templateData.senderName || 'Gmail API Bot'}</p>
                </div>
                <div class="footer">
                    <p>This email was sent automatically via Gmail API</p>
                </div>
            </div>
        </body>
        </html>
        `;
        
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const encodedMessage = createEmailMessage(to, subject, htmlBody, from);
        
        const result = await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: encodedMessage
            }
        });
        
        res.json({
            success: true,
            messageId: result.data.id,
            message: 'Template email sent successfully!'
        });
        
    } catch (error) {
        console.error('Error sending template email:', error);
        res.status(500).json({ 
            error: 'Failed to send template email',
            details: error.message 
        });
    }
});
app.get('/auth/status', async (req, res) => {
    try {
        const hasCredentialsFile = await fs.access(CREDENTIALS_PATH).then(() => true).catch(() => false);
        const hasTokenFile = await fs.access(TOKEN_PATH).then(() => true).catch(() => false);
        
        res.json({
            hasCredentialsFile,
            hasTokenFile,
            isAuthenticated: !!(oauth2Client && oauth2Client.credentials.access_token)
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * Create OAuth2 client with provided credentials
 */
async function createOAuth2ClientWithCreds(credentials) {
    const { client_secret, client_id, redirect_uris } = credentials.installed || credentials.web;
    
    const tempOAuth2Client = new google.auth.OAuth2(
        client_id,
        client_secret,
        redirect_uris[0] || 'http://localhost:3000/auth/callback'
    );
    
    return tempOAuth2Client;
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



async function readPublicKeys() {
    const publicKeyText = await fs.promises.readFile('public-key-directory.txt', 'utf8');
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

/**
 * Placeholder test function - replace with your custom logic
 * @param {object} cliArgs - All CLI arguments from request body
 * @returns {object} - {passed: boolean, reason?: string, details?: object}
 */
async function shouldSendEmail(cliArgs) {
    // Example implementation: check message length > 37 bytes
    // Replace this function with your custom test logic
    const {message, groupMembers, proof, publicInputs} = cliArgs; 
    const publicKeys = await readPublicKeys();
    //console.log("Public keys:", publicKeys);

    const groupMembersS = groupMembers.split(',').sort();
    const groupMembersPublicKeys = groupMembersS.map(member => publicKeys.get(member));
    //const keylist_array = inputPublicKeysRef.current.value.split("\\");
    const keylist_array = groupMembersPublicKeys;
    let keylist_registers = [];
    for (let i = 0; i < keylist_array.length; i++){
        keylist_registers.push(bigint_to_registers(121n,34,SignatureProcessing.parseSSHRSAPublicKey(keylist_array[i]).modulusBigInt));
    }
    const zero_register = Array(34).fill("0");
    for (let i = keylist_array.length; i < 1000; i++){
        keylist_registers.push(zero_register);
    }
    const modulusLength = 512; // parseInt(inputModulusLengthRef.current.value);
    const msg_register = bigint_to_registers(121n,34,SignatureProcessing.generatePKCS1BigInt(message, "kudosBot", "SHA-512", modulusLength));

    const vkey = JSON.parse(await fs.promises.readFile("verification_key-rsa.json", 'utf8'));

    //const publicSignals = JSON.parse(inputPublicRef.current.value);
    //const proof = JSON.parse(inputProofRef.current.value);
    //verify msg
    console.log(message);
    console.log(message.length);
    console.log(msg_register);
    console.log(keylist_registers);
    console.log(publicInputs);
    let res = true;
    for (let i = 0; i < 34; i++){
        if (publicInputs[i] !== msg_register[i]){
            res = false;
            break;
        }
    }
    //verify keylist
    if (res){
        for (let j = 0; j < keylist_registers.length * 34; j++){
            if (publicInputs[j+34] !== keylist_registers[Math.floor(j/34)][j%34]){
                res = false;
                break;
            }
        }
    }
    if (res){
        console.log(proof);
        console.log(publicInputs);
        res = await snarkjs.groth16.verify(vkey, publicInputs, proof);
    }

    
    
    return {
        passed: res,
        details: {
            test: "test"
        }
    };
}

/**
 * CLI request endpoint - accepts message and sends email if test passes
 * Uses server's OAuth2 credentials automatically
 */
app.post('/cli/send', async (req, res) => {
    try {
        const { message, to, subject, groupMembers } = req.body;
        
        if (!message) {
            return res.status(400).json({ 
                error: 'Message is required' 
            });
        }
        
        // Run the test function with all CLI arguments
        const testResult = await shouldSendEmail(req.body);
        
        if (!testResult.passed) {
            return res.json({
                success: false,
                message: testResult.reason || 'Test failed',
                ...testResult.details
            });
        }
        
        // Initialize OAuth2 client if not already done
        if (!oauth2Client) {
            await createOAuth2Client();
            const hasToken = await loadSavedToken();
            
            if (!hasToken) {
                return res.status(503).json({ 
                    error: 'Server not authenticated. Administrator must visit /auth first to set up OAuth2 credentials.' 
                });
            }
        }
        
        // Default recipient and subject if not provided
        const recipient = to || 'sansome-talk@0xparc.org';
        const emailSubject = subject || 'double-blind message';
        
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const encodedMessage = createEmailMessage(recipient, emailSubject, message + "\n==========\n"+groupMembers.split(',').sort());
        
        const result = await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: encodedMessage
            }
        });
        
        console.log(`Email sent successfully. ID: ${result.data.id}`);
        
        res.json({
            success: true,
            messageId: result.data.id,
            threadId: result.data.threadId,
            sentTo: recipient,
            subject: emailSubject,
            message: 'Email sent successfully!',
            testDetails: testResult.details
        });
        
    } catch (error) {
        console.error('Error processing CLI request:', error);
        res.status(500).json({ 
            error: 'Failed to process CLI request',
            details: error.message 
        });
    }
});

/**
 * Root endpoint with instructions
 */
app.get('/', (req, res) => {
    res.json({
        message: 'Gmail OAuth2 Server',
        endpoints: {
            '/auth': 'Start authentication flow',
            '/auth/status': 'Check authentication status',
            '/test-gmail': 'Test Gmail API access',
            '/gmail/messages': 'Get Gmail messages',
            '/gmail/send': 'Send simple email (POST)',
            '/gmail/send-with-attachment': 'Send email with attachments (POST)',
            '/gmail/send-template': 'Send HTML template email (POST)',
            '/cli/send': 'CLI endpoint - send email if test passes (POST)'
        },
        setup: [
            '1. Download credentials.json from Google Cloud Console',
            '2. Place it in the project root directory',
            '3. Visit /auth to start authentication'
        ]
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Visit http://localhost:${PORT}/auth to start authentication`);
    console.log(`Check status at http://localhost:${PORT}/auth/status`);
});
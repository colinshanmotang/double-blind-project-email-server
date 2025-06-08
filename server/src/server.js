const express = require('express');
const app = express();
const port = 3000;

// Middleware for parsing JSON bodies
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Basic test endpoint
app.post('/sendMessage', (req, res) => {
    const { groupMembers, message, proof, publicInputs } = req.body;
    console.log(`Received request - Group members: ${groupMembers}, Message: ${message}`);
    console.log('Proof:');
    console.log(proof);
    console.log('Public inputs:');
    console.log(publicInputs);
    res.json({ 
        received: true,
        groupMembers,
        message,
        proof,
        publicInputs
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 
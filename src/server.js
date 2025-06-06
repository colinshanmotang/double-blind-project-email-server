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
app.post('/test', (req, res) => {
    const { filename, message } = req.body;
    console.log(`Received request - File: ${filename}, Message: ${message}`);
    res.json({ 
        received: true,
        filename,
        message
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
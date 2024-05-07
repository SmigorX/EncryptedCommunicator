const http = require('http');
const fs = require('fs');
const https = require('https');

const server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/send-text') {
        let data = '';
        req.on('data', chunk => {
            data += chunk;
        });
        req.on('end', () => {
            console.log('Received text:', data);

            const options = {
                hostname: 'client-backend',
                port: 5002,
                path: '/',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/text'
                }
            };

            const request = https.request(options, response => {
                console.log(`Response from client-backend: ${response.statusCode}`);
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end('Text received and forwarded successfully');
            });

            request.on('error', error => {
                console.error('Error making POST request to client-backend:', error);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Error forwarding text');
            });

            request.write(data);
            request.end();
        });

    } else if (req.url === '/') {
        // Serve the HTML file
        fs.readFile('index.html', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Error loading index.html');
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(data);
            }
        });
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

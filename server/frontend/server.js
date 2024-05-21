const http = require('http');
const fs = require('fs');


const server = http.createServer((req, res) => {
    if (req.url === '/data') {
        const backendUrl = 'http://127.0.0.1:5006/messages';
        http.get(backendUrl, (backendRes) => {
            let responseData = '';

            backendRes.on('data', (chunk) => {
                responseData += chunk;
            });

            backendRes.on('end', () => {
                res.writeHead(200, {'Content-Type': 'application/json'});
                res.end(responseData);
            });
        }).on('error', (err) => {
            console.error('Error fetching data from backend:', err);
            res.writeHead(500);
            res.end('Error fetching data from backend');
        });
    } else {
        fs.readFile('./index.html', (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end('Error loading index.html');
            } else {
                res.writeHead(200, {'Content-Type': 'text/html'});
                res.end(data);
            }
        });
    }
});

const PORT = process.env.PORT;

server.listen(PORT, () => {
    console.log(`Server running at http://0.0.0.0:${PORT}/`);
});
wrap it all in some nginx for nice routes?
write a compose file
route all those things

1. Server:
    1.1. Backend:
        - Rust backend that receives messages on websocket, writes it to a file
            * Exposes 5000 for the socket listener
        - Nginx that exposes the content of that file on an endpoint
    1.2. Frontend:
        - Node server to serve the html (exchange for nginx?)
        - HTML on a cycle reads the endpoint from nginx and displays the messages
1. Client:
    2.1. Backend:
        - Receives message on an endpoint, sends it over websocket
    2.2. Frontend:
        - Node server to serve the html (again, maybe nginx?)
        - HTML takes inputted text and sends a request to backend endpoint


Internal Ports:
Server-backend:
- NGINX on 5004 redirecting to:
    * /messages -> *.txt file
    * /backend -> 5005 port for backend
Server-frontend:
- To public: 5001
Client-backend
- backend: 5004
- frontend: 5002
Client-frontend
- To public: 5003
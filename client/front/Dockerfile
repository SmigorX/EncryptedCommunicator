FROM node:alpine

COPY index.html /usr/src/app/index.html
COPY server.js /usr/src/app/server.js

ENV PORT=5003

EXPOSE 5003

ENTRYPOINT node /usr/src/app/server.js

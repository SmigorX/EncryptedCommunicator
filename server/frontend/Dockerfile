FROM node:alpine

WORKDIR /usr/src/app
COPY index.html /usr/src/app/index.html
COPY server.js /usr/src/app/server.js

RUN adduser --disabled-password appuser
RUN chown -R appuser /usr/src/app

USER appuser

ENTRYPOINT node /usr/src/app/server.js

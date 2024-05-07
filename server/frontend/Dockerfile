FROM node:alpine

WORKDIR /usr/src/app
COPY index.html /usr/src/app/index.html
COPY server.js /usr/src/app/server.js

RUN adduser --disabled-password appuser
RUN chown -R appuser /usr/src/app

ENV PORT=5001

EXPOSE 5001

USER appuser

ENTRYPOINT node /usr/src/app/server.js

FROM node:24.19.0-slim

WORKDIR /app

RUN npm init -y && \
    npm install express@5 body-parser@2

COPY server.js .

EXPOSE 3000

CMD ["node", "server.js"]

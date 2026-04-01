FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
RUN npm install -g @anthropic-ai/claude-code
COPY server.js .
COPY public/ ./public/
RUN mkdir -p data
EXPOSE 8095
CMD ["node", "server.js"]

# HLPA-DS REST API (Node.js / Express)
FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json* ./
# dev dependencies kept so `npm test` works inside the container
RUN npm install --include=dev --no-audit --no-fund
COPY src ./src
COPY test ./test
USER node
EXPOSE 4000
CMD ["node", "src/server.js"]

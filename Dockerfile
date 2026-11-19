FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server ./server
COPY src ./src
COPY securepay ./securepay
USER node
EXPOSE 8080
CMD ["node","server/index.js"]

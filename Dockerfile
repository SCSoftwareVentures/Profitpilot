FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
ARG PROFITPILOT_BUILD_REVISION=unverified
RUN printf '%s\\n' "$PROFITPILOT_BUILD_REVISION" > /app/BUILD_REVISION
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY server ./server
COPY src ./src
USER node
EXPOSE 8080
CMD ["node","server/index.js"]

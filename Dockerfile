# Build dependencies in a disposable stage; package managers are not runtime requirements.
FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# Retain the tested Node/musl ABI, patch distribution packages and strip bundled build tooling.
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN apk upgrade --no-cache && \
    rm -rf /usr/local/lib/node_modules /opt/yarn* /usr/local/include/node /root/.npm /root/.cache && \
    rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg && \
    node --version && ! command -v npm && ! command -v yarn
COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY src ./src
USER node
EXPOSE 8080
CMD ["node","server/index.js"]

# Optional protected image. Mount independently maintained signature definitions read-only.
FROM runtime AS protected
USER root
RUN apk add --no-cache clamav && apk upgrade --no-cache && test -x /usr/bin/clamscan
USER node

# Default build remains the synthetic prototype.
FROM runtime AS prototype

FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY server ./server
COPY src ./src
USER node
EXPOSE 8080
CMD ["node","server/index.js"]

# Optional protected image. Mount independently maintained signature definitions read-only.
FROM runtime AS protected
USER root
RUN apk add --no-cache clamav && test -x /usr/bin/clamscan
USER node

# Default build remains the synthetic prototype; select --target protected deliberately.
FROM runtime AS prototype

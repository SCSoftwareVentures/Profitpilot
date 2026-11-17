# Keep package managers and their transitive dependencies out of the final image.
FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && rm -rf /usr/local/lib/node_modules /opt/yarn* /root/.npm /root/.cache /home/node/.npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/corepack
# Flatten the pruned root filesystem: removed tools do not survive in lower layers.
FROM scratch
COPY --from=dependencies / /
ENV NODE_ENV=production
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /app
ARG PROFITPILOT_BUILD_REVISION=unverified
RUN printf '%s' "$PROFITPILOT_BUILD_REVISION" > /app/BUILD_REVISION
COPY server ./server
COPY src ./src
USER node
EXPOSE 8080
CMD ["node","server/index.js"]

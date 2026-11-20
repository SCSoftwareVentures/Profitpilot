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

# Assemble a genuine minimal package-managed root filesystem for the prototype.
# The signed APK inventory is retained; no package record is removed or fabricated.
FROM node:22-alpine AS prototype-root
RUN mkdir -p /rootfs/etc/apk/keys /rootfs/usr/local/bin /rootfs/app /rootfs/home/node /rootfs/tmp /rootfs/var/tmp && \
    cp /etc/apk/keys/* /rootfs/etc/apk/keys/ && \
    cp /etc/apk/repositories /rootfs/etc/apk/repositories && \
    apk --root /rootfs --initdb --no-scripts --no-cache add musl libgcc libstdc++ ca-certificates-bundle libcrypto3 libssl3 zlib && \
    ! apk --root /rootfs info -e busybox && ! apk --root /rootfs info -e busybox-binsh && ! apk --root /rootfs info -e ssl_client && \
    cp -L /etc/os-release /rootfs/etc/os-release && cp /etc/alpine-release /rootfs/etc/alpine-release && \
    printf '%s\n' 'root:x:0:0:root:/root:/sbin/nologin' 'node:x:1000:1000:node:/home/node:/sbin/nologin' > /rootfs/etc/passwd && \
    printf '%s\n' 'root:x:0:' 'node:x:1000:' > /rootfs/etc/group && \
    chown 1000:1000 /rootfs/home/node && chmod 1777 /rootfs/tmp /rootfs/var/tmp && \
    test -s /rootfs/lib/apk/db/installed && test -s /rootfs/etc/ssl/cert.pem && \
    test ! -e /rootfs/bin/busybox && test ! -e /rootfs/bin/sh

# Default synthetic API image: no shell, BusyBox, wget or package manager.
FROM scratch AS prototype
COPY --from=prototype-root /rootfs/ /
COPY --from=dependencies /usr/local/bin/node /usr/local/bin/node
COPY --from=dependencies /app/node_modules /app/node_modules
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY src ./src
ENV NODE_ENV=production HOME=/home/node PATH=/usr/local/bin:/usr/bin:/bin
USER 1000:1000
EXPOSE 8080
CMD ["/usr/local/bin/node","server/index.js"]

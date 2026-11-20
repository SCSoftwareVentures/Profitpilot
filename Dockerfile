# Install locked dependencies in the official Node build environment.
FROM node:22-trixie-slim AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# Clean runtime from the matching Debian release: no BusyBox and no bundled npm.
FROM debian:trixie-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN apt-get update && apt-get -y upgrade && \
    apt-get install -y --no-install-recommends ca-certificates libstdc++6 libgcc-s1 libatomic1 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 1000 node && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin node
COPY --from=dependencies /usr/local/bin/node /usr/local/bin/node
COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY src ./src
RUN node --version && ! command -v busybox && ! command -v wget && ! command -v npm
USER 1000:1000
EXPOSE 8080
CMD ["node","server/index.js"]

# The scanner's distribution packages and their dependency inventory stay intact.
FROM runtime AS protected
USER root
RUN apt-get update && apt-get install -y --no-install-recommends clamav && \
    apt-get -y upgrade && rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/lib/clamav && test -x /usr/bin/clamscan && \
    ! command -v busybox && ! command -v wget
USER 1000:1000

FROM runtime AS prototype

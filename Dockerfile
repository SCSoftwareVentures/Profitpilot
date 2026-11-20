# Build dependencies in a disposable stage; package managers are not runtime requirements.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# Assemble a genuine minimal package-managed root filesystem for the prototype.
# The signed APK inventory is retained; no package record is removed or fabricated.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS prototype-root
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
FROM scratch AS api-runtime
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

# Compile only a bounded stdin adapter against the vendor's libclamav headers.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS scanner-build
RUN apk add --no-cache build-base clamav-dev
COPY native/scan-source.c /build/scan-source.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -fanalyzer -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -o /build/profitpilot-scan /build/scan-source.c -lclamav
RUN cc -DPROFITPILOT_FIXTURE_ONLY -std=c11 -O2 -Wall -Wextra -Werror -fanalyzer -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -o /build/profitpilot-scan-fixture /build/scan-source.c -lclamav

# Install the signed runtime libraries, not freshclam, daemon or shell packages.
FROM prototype-root AS protected-root
RUN apk --root /rootfs --no-scripts --no-cache add clamav-libs clamav-libunrar && \
    ! apk --root /rootfs info -e busybox && ! apk --root /rootfs info -e busybox-binsh && ! apk --root /rootfs info -e ssl_client && \
    mkdir -p /rootfs/var/lib/clamav && chmod 755 /rootfs/var/lib/clamav && \
    test ! -e /rootfs/bin/sh && \
    test -s /rootfs/lib/apk/db/installed

FROM api-runtime AS protected
COPY --from=protected-root /rootfs/ /
COPY --from=scanner-build /build/profitpilot-scan /usr/local/bin/profitpilot-scan
USER 1000:1000

# CI-only scanner variant; never used for releases or protected deployment.
FROM api-runtime AS scanner-fixture
COPY --from=protected-root /rootfs/ /
COPY --from=scanner-build /build/profitpilot-scan-fixture /usr/local/bin/profitpilot-scan
USER 1000:1000

# Keep ordinary builds synthetic by default.
FROM api-runtime AS prototype

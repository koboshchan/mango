# syntax=docker/dockerfile:1
#
# Prod image for SecureCord: client + server are both built here, so the
# only thing shipped in the final stage is compiled/bundled JS - no
# TypeScript source, no npx/tsx, no node_modules. Build context is the repo
# root (docker-compose.yml's `build.context: .`) because both client/ and
# server/ need to be reachable from a single build.

# ---- Stage 1: build the static client bundle ----
FROM node:24.22.1-alpine AS client-builder
WORKDIR /app/client
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client/ ./
RUN npm run build
# Produces client/dist/{index.html,bundle.js,bundle.js.map}

# ---- Stage 2: bundle the server into a single CJS file ----
FROM node:24.22.1-alpine AS server-builder
WORKDIR /app/server
COPY server/package.json server/package-lock.json ./
RUN npm ci
COPY server/ ./
# --format=cjs (not esm) is required, not stylistic: mongodb and ws
# require() a handful of optional native addons (kerberos, snappy,
# @mongodb-js/zstd, aws4, socks, @aws-sdk/credential-providers,
# gcp-metadata, mongodb-client-encryption, bufferutil, utf-8-validate)
# inside try/catch, none of which are installed here. Under CJS a missing
# require() stays a caught runtime error exactly like it would unbundled;
# under ESM, esbuild would need to statically resolve those imports at
# build time and fail. --external keeps esbuild from trying to bundle them
# so the try/catch fallback behavior is preserved.
RUN npx esbuild src/index.ts \
    --bundle \
    --platform=node \
    --target=node24 \
    --format=cjs \
    --outfile=dist/server.cjs \
    --external:kerberos \
    --external:snappy \
    --external:@mongodb-js/zstd \
    --external:aws4 \
    --external:socks \
    --external:@aws-sdk/credential-providers \
    --external:gcp-metadata \
    --external:mongodb-client-encryption \
    --external:bufferutil \
    --external:utf-8-validate

# ---- Stage 3: runtime image - no source, no node_modules ----
FROM node:24.22.1-alpine AS runner
WORKDIR /app

COPY --from=server-builder /app/server/dist/server.cjs ./server.cjs
COPY --from=client-builder /app/client/dist ./public

RUN mkdir -p /app/data/keys && chown -R node:node /app
USER node

EXPOSE 8080

CMD ["node", "server.cjs"]

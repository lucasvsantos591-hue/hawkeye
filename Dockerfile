FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:20-alpine
LABEL org.opencontainers.image.description="Hawkeye: reachability-aware dependency vulnerability analysis"
ENV NODE_ENV=production \
    HAWKEYE_HOST=0.0.0.0 \
    HAWKEYE_PORT=3000 \
    HAWKEYE_ALLOWED_ROOT=/workspace
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./
RUN mkdir -p /workspace && chown node:node /workspace
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# The API refuses to start without HAWKEYE_API_TOKEN. For one-off CLI scans:
#   docker run --rm -v "$PWD:/workspace:ro" hawkeye node dist/cli/index.js analyze /workspace --no-cache
CMD ["node", "dist/cli/server.js"]

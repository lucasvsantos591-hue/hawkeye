FROM node:18-alpine

LABEL maintainer="Hawkeye Contributors"
LABEL description="Precision Vulnerability Reachability Analysis"

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built application
COPY dist ./dist

# Create cache directory
RUN mkdir -p .hawkeye-cache

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

# Start API server
CMD ["node", "dist/cli/server.js"]

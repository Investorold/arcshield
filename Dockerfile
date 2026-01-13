# ArcShield Web Dashboard - Production Dockerfile

# Build stage
FROM node:20-slim AS builder

WORKDIR /app

# Copy all package files (including CLI for workspace resolution)
COPY package*.json ./
COPY packages/core/package*.json ./packages/core/
COPY packages/cli/package*.json ./packages/cli/
COPY packages/web/package*.json ./packages/web/

# Install dependencies
RUN npm ci

# Copy source code
COPY packages/core ./packages/core
COPY packages/cli ./packages/cli
COPY packages/web ./packages/web
COPY tsconfig.json ./

# Build core package first (dependency for others)
RUN npm run build --workspace=@arcshield/core

# Build web package (frontend + server)
RUN npm run build --workspace=@arcshield/web

# Production stage
FROM node:20-slim AS runner

# Install git for cloning repositories (v2)
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all package files for workspace resolution
COPY package*.json ./
COPY packages/core/package*.json ./packages/core/
COPY packages/cli/package*.json ./packages/cli/
COPY packages/web/package*.json ./packages/web/

# Install production dependencies
RUN npm ci --omit=dev

# Copy built files
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/web/dist ./packages/web/dist

# Copy rule JSON files (not compiled, just copied)
COPY --from=builder /app/packages/core/src/rules/builtin ./packages/core/dist/rules/builtin

# Copy package.json files needed at runtime
COPY --from=builder /app/packages/core/package.json ./packages/core/
COPY --from=builder /app/packages/web/package.json ./packages/web/

# Create scans directory
RUN mkdir -p /root/.arcshield/scans

# Set environment
ENV NODE_ENV=production
ENV PORT=3501

# Expose port
EXPOSE 3501

# Start server
WORKDIR /app/packages/web
CMD ["node", "dist/api/server.js"]


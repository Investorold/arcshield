# ArcShield Web Dashboard - Production Dockerfile

# Build stage
FROM node:20-slim AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/core/package*.json ./packages/core/
COPY packages/web/package*.json ./packages/web/

# Install dependencies
RUN npm ci

# Copy source code
COPY packages/core ./packages/core
COPY packages/web ./packages/web
COPY tsconfig.json ./

# Build core package
RUN npm run build --workspace=@arcshield/core

# Build web package (frontend + server)
RUN npm run build --workspace=@arcshield/web

# Production stage
FROM node:20-slim AS runner

WORKDIR /app

# Install production dependencies only
COPY package*.json ./
COPY packages/core/package*.json ./packages/core/
COPY packages/web/package*.json ./packages/web/

RUN npm ci --omit=dev

# Copy built files
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/web/dist ./packages/web/dist

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

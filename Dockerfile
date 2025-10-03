# Builder stage
FROM node:18-bullseye-slim AS builder
WORKDIR /app

COPY . .
RUN apt-get update -y && apt-get install g++ python3 make -y && yarn cache clean && yarn install && yarn build && rm -rf node_modules/ && yarn install --production

# Production stage
FROM node:18-bullseye-slim AS production
WORKDIR /app

COPY --from=builder /app/package.json .
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/public ./public

ENV NODE_ENV=production

EXPOSE 8002

CMD ["node", "./dist/src/app.js"]

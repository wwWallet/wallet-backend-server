# Builder stage
FROM node:18-bullseye-slim AS builder
WORKDIR /app

COPY . .
COPY ./config/config.template.ts ./config/index.ts
RUN apt-get update -y && apt-get install g++ python3 make -y && yarn cache clean && yarn install && yarn build

# Production stage
FROM node:18-bullseye-slim AS production
WORKDIR /app

COPY --from=builder /app/package.json .
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public



RUN apt-get update -y && apt-get install g++ python3 make -y && yarn install --production

ENV NODE_ENV=production

EXPOSE 8002

CMD ["node", "./dist/src/app.js"]

# Builder stage
FROM node:18-bullseye-slim AS builder
WORKDIR /home/node/app

COPY . .
RUN apt-get update -y && apt-get install g++ python3 make -y && yarn cache clean && yarn install && yarn build

# Production stage
FROM node:18-bullseye-slim AS production
WORKDIR /home/node/app

COPY --from=builder /home/node/app/package.json .
COPY --from=builder /home/node/app/.npmrc .
COPY --from=builder /home/node/app/dist ./dist
COPY --from=builder /home/node/app/public ./public



RUN apt-get update -y && apt-get install g++ python3 make -y && yarn install --production

ENV NODE_ENV production

EXPOSE 8002

CMD ["node", "./dist/src/app.js"]
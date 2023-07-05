# Builder stage
FROM node:16-alpine3.16 AS builder
WORKDIR /home/node/app

COPY . .
RUN yarn cache clean && yarn --frozen-lockfile && yarn build

# Production stage
FROM node:16-alpine3.16 AS production
WORKDIR /home/node/app

COPY --from=builder /home/node/app/package.json .
COPY --from=builder /home/node/app/.npmrc .
COPY --from=builder /home/node/app/dist ./dist



RUN yarn install --production

ENV NODE_ENV production
EXPOSE 8003

CMD ["node", "./dist/src/app.js"]
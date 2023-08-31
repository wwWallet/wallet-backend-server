FROM node:16-bullseye-slim

WORKDIR /home/node/app

COPY . .

RUN yarn cache clean && yarn install --frozen-lockfile


CMD ["tail", "-f", "/dev/null"]
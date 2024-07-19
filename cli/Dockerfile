FROM node:16-bullseye-slim

WORKDIR /home/node/app

COPY . .

RUN yarn cache clean && yarn install


CMD ["tail", "-f", "/dev/null"]

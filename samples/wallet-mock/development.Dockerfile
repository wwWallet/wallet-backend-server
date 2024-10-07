FROM node:16-bullseye-slim
WORKDIR /home/node/app

# Copy package.json and yarn.lock to the container
COPY package.json yarn.lock ./
# RUN apt update -y && apt install python3 -y

RUN mkdir -p /home/node/app/node_modules
COPY --chown=node:node . .
RUN yarn cache clean && yarn install


# Copy the rest of the application code to the container

ENV NODE_ENV=development


RUN chown -R node:node  /home/node/app/node_modules
USER node
CMD ["yarn", "dev"]

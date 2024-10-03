FROM node:16-bullseye-slim as dependencies

WORKDIR /dependencies

# Install dependencies first so rebuild of these layers is only needed when dependencies change
COPY package.json yarn.lock ./
RUN --mount=type=secret,id=npmrc,required=true,target=./.npmrc,uid=1000 \
		yarn cache clean && yarn install


FROM node:16-bullseye-slim as development

ENV NODE_PATH=/node_modules
COPY --from=dependencies /dependencies/node_modules /node_modules

WORKDIR /app
ENV NODE_ENV development
CMD ["yarn", "dev-docker"]

# Set user last so everything is readonly by default
USER node

# Don't need the rest of the sources since they'll be mounted from host

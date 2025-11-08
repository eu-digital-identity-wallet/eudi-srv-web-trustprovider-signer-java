FROM node:18-slim AS nodejs_builder

WORKDIR /opt/app/client

COPY ./package.json ./package.json
RUN npm install
COPY . .
EXPOSE 3000
ENTRYPOINT ["npm", "start"]
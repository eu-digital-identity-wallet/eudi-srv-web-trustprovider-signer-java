FROM node:18-slim AS nodejs_builder

WORKDIR /opt/app/client

COPY ./package.json ./package.json
COPY ./package-lock.json ./package-lock.json

# Install dependencies
RUN npm install

# Copy the rest of your application files
COPY . .

EXPOSE 3000

ENTRYPOINT ["npm", "start"]
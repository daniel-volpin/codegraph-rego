# Frontend Dockerfile
FROM node:20-slim

WORKDIR /app

# Copy package files
COPY package.json yarn.lock ./

# Install dependencies
RUN yarn install

# Copy source code
COPY . .

# Expose port
EXPOSE 5173

# Command (Development mode)
CMD ["yarn", "dev", "--host"]

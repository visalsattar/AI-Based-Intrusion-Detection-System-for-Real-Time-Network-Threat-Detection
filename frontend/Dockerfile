# frontend/Dockerfile
# Use official Node.js image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy the rest of the React code
COPY . .

# Expose the React development port
EXPOSE 3000

# Start the React app
CMD ["npm", "start"]
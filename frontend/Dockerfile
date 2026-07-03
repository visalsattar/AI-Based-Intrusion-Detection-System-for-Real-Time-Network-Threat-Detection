# frontend/Dockerfile — DEVELOPMENT MODE ONLY
#
# This Dockerfile runs the React dev server (hot-reload, source maps).
# It is NOT used by docker-compose.yml for normal operation.
#
# For production / demo:
#   docker-compose up --build
#   (React is compiled inside backend/Dockerfile via the multi-stage build)
#
# For frontend-only development against a locally running Flask backend:
#   docker build -t ids-frontend . && docker run -p 3000:3000 ids-frontend
#   (Flask must be running on the host at port 5000 for the proxy to work)

FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

EXPOSE 3000

CMD ["npm", "start"]

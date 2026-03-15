FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173
# Runs the Vite/React dev server with host flag for Docker access
CMD ["npm", "run", "dev", "--", "--host"]
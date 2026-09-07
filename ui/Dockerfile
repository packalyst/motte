# Production build stage
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
# README.md (single source for the About architecture section) lives at the repo root, which
# is outside this build's ./ui context — pull it from the "root" named context to /README.md,
# where the `../../../README.md` import in src/views resolves.
COPY --from=root README.md /README.md
RUN npm run build

# Production runtime stage (default)
FROM nginx:alpine AS production
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

# Development stage - Vite dev server with hot reload
FROM node:22-alpine AS development
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
COPY --from=root README.md /README.md
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

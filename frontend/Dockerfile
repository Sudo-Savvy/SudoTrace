FROM node:20.19-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN rm /etc/nginx/conf.d/default.conf.bak 2>/dev/null || true
COPY nginx-entrypoint.sh /docker-entrypoint.d/10-generate-certs.sh
RUN chmod +x /docker-entrypoint.d/10-generate-certs.sh
EXPOSE 443

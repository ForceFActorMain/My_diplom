FROM nginx:alpine

WORKDIR /app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser

CMD ["nginx", "-g", "daemon off;"]

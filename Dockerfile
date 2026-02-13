# syntax=docker/dockerfile:1

FROM node:20-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production
ENV DEBIAN_FRONTEND=noninteractive

# Paquetes mínimos + init para señales correctas (evita zombies)
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    qpdf \
    ghostscript \
    dumb-init \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Instalar dependencias primero (mejor cache)
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copiar el resto del proyecto
COPY . .

# Crear usuario no-root
RUN useradd -m -u 10001 appuser \
  && mkdir -p /app/tmp/uploads /app/tmp/out \
  && chown -R appuser:appuser /app

USER appuser

# Render suele inyectar PORT; usa 10000 como default
ENV PORT=10000
EXPOSE 10000

# Healthcheck (útil para diagnóstico)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||10000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.mjs"]


FROM node:22-alpine AS frontend
WORKDIR /build/frontend
RUN npm install -g pnpm@11.19.0
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm run build

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home sentinel
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY --from=frontend /build/app/static ./app/static
USER sentinel
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health',timeout=3)"
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]

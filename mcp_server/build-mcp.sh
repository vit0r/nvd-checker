#!/bin/bash
set -e

# Se o usuário passar um argumento, usará como tag da imagem. 
# Caso contrário, o padrão será "nvd-checker-mcp:latest"
IMAGE_TAG=${1:-nvd-checker-mcp:latest}

echo "🛠️  Iniciando o build da imagem do MCP Server..."
echo "🏷️  Tag da imagem: $IMAGE_TAG"
echo "📂 Contexto do build: $(pwd)"
echo "📄 Dockerfile: mcp_server/Dockerfile"
echo "--------------------------------------------------------"

# Executa o build utilizando o Dockerfile dentro da pasta mcp_server,
# mas mantendo o contexto de build (.) na raiz para copiar a pasta 'cli/'
docker build -f mcp_server/Dockerfile -t "$IMAGE_TAG" .

echo "--------------------------------------------------------"
echo "✅ Build finalizado com sucesso!"
echo ""
echo "🚀 Para testar a imagem localmente, execute:"
echo "   docker run -p 8000:8000 -e NVD_API_KEY=<sua-key-aqui> $IMAGE_TAG"

# NVD Checker — MCP Server Implementation Plan

Criar um **MCP Server** que expõe as funcionalidades do `nvd-checker` como tools.

## Proposed Changes

### Estrutura de Diretórios
```
mcp_server/            # MCP Server
├── pyproject.toml     # Build config
├── mcp_server/        # Package
│   ├── __init__.py
│   ├── server.py      # FastMCP server com tools
│   ├── tools.py       # Funções de tool (scan, check, report)
│   └── repo_manager.py# Clone/gerenciamento de repos temporários
```

### MCP Server (`mcp_server/`)

O MCP Server expõe as funcionalidades do `nvd-checker` como tools MCP usando **FastMCP** com transporte **Streamable HTTP**.

#### `server.py`
Export ASGI app para Uvicorn configurando o FastMCP.

#### `tools.py`
Define 3 tools MCP que encapsulam a CLI do nvd-checker:
- `scan_repository`
- `check_dependency`
- `generate_report`

#### `repo_manager.py`
Gerencia clone temporário de repositórios Git usando `tempfile`.

## Verification Plan
1. **MCP Server**: Testes unitários para cada tool com mocks do NVD
2. **MCP Server local**: Rodar server e testar com MCP Inspector
   ```bash
   uvicorn mcp_server.server:app --host 0.0.0.0 --port 8000
   npx @modelcontextprotocol/inspector http://localhost:8000/mcp
   ```

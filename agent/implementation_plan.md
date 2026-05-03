# NVD Checker — AI Agent Implementation Plan

Criar um **AI Agent** que se conecta ao MCP Server via protocolo MCP.

## Proposed Changes

### Estrutura de Diretórios
```
agent/                 # AI Agent
├── pyproject.toml     # Build config
├── agent/             # Package
│   ├── __init__.py
│   ├── main.py        # Entry point do agent
│   └── prompts.py     # System prompts e instruções
```

### AI Agent (`agent/`)

O agent usa **OpenAI Agents SDK** com suporte nativo a MCP.

#### `main.py`
Inicia um MCPServerStreamableHttp apontando para a URL do servidor MCP e roda o Agent interativo.

#### `prompts.py`
System prompt que instrui o agent a interpretar prompts do usuário, extrair URLs e usar as ferramentas do MCP.

## Verification Plan
1. **Agent end-to-end**: Testar agent contra server local
   ```bash
   MCP_SERVER_URL=http://localhost:8000/mcp python -m agent.main
   ```

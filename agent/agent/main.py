"""
NVD Security Agent — interactive AI agent that connects to the
NVD Checker MCP Server to scan and analyze project vulnerabilities.

Usage:
    # Start with default MCP server URL
    python -m agent.main

    # Specify a remote MCP server (e.g., running on Kubernetes)
    MCP_SERVER_URL=https://nvd-mcp.example.com/mcp python -m agent.main

    # Non-interactive mode (single prompt)
    python -m agent.main --prompt "corrija as vulnerabilidades do projeto https://github.com/user/repo"
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp

from agent.prompts import SYSTEM_PROMPT

DEFAULT_MCP_URL = "http://localhost:8000/mcp"
DEFAULT_MODEL = "gpt-4o"


async def run_interactive(mcp_url: str, model: str) -> None:
    """Run the agent in interactive REPL mode."""
    print("\n🛡️  NVD Security Agent")
    print(f"   MCP Server: {mcp_url}")
    print(f"   Model: {model}")
    print("   Digite 'sair' ou 'exit' para encerrar.\n")

    async with MCPServerStreamableHttp(
        url=mcp_url,
        name="NVD Checker MCP",
        cache_tools_list=True,
    ) as mcp_server:
        agent = Agent(
            name="NVD Security Agent",
            model=model,
            instructions=SYSTEM_PROMPT,
            mcp_servers=[mcp_server],
        )

        while True:
            try:
                user_input = input("🛡️  > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n\n👋 Até logo!")
                break

            if not user_input:
                continue
            if user_input.lower() in ("sair", "exit", "quit", "q"):
                print("\n👋 Até logo!")
                break

            try:
                print("\n⏳ Processando...\n")
                result = await Runner.run(agent, user_input)
                print(result.final_output)
                print()
            except Exception as e:
                print(f"\n❌ Erro: {e}\n")


async def run_single(mcp_url: str, model: str, prompt: str) -> None:
    """Run the agent with a single prompt (non-interactive)."""
    async with MCPServerStreamableHttp(
        url=mcp_url,
        name="NVD Checker MCP",
        cache_tools_list=True,
    ) as mcp_server:
        agent = Agent(
            name="NVD Security Agent",
            model=model,
            instructions=SYSTEM_PROMPT,
            mcp_servers=[mcp_server],
        )

        result = await Runner.run(agent, prompt)
        print(result.final_output)


def main() -> None:
    """Entry point for the NVD Security Agent."""
    parser = argparse.ArgumentParser(
        description="NVD Security Agent — AI-powered vulnerability analysis",
    )
    parser.add_argument(
        "--mcp-url",
        default=os.getenv("MCP_SERVER_URL", DEFAULT_MCP_URL),
        help=f"MCP Server URL (default: {DEFAULT_MCP_URL})",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("AGENT_MODEL", DEFAULT_MODEL),
        help=f"LLM model to use (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--prompt", "-p",
        default=None,
        help="Single prompt to execute (non-interactive mode)",
    )
    args = parser.parse_args()

    # Validate OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ OPENAI_API_KEY não definida. Defina a variável de ambiente:")
        print("   export OPENAI_API_KEY=sk-...")
        sys.exit(1)

    if args.prompt:
        asyncio.run(run_single(args.mcp_url, args.model, args.prompt))
    else:
        asyncio.run(run_interactive(args.mcp_url, args.model))


if __name__ == "__main__":
    main()

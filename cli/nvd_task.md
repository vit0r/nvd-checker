# NVD Checker — Implementation Tasks

## Project Setup
- [x] Create `pyproject.toml`
- [x] Create `.gitignore`
- [x] Create `README.md`
- [x] Create `nvd_checker/__init__.py`
- [x] Create `nvd_checker/__main__.py`

## Scanner de Dependências
- [x] `nvd_checker/scanner/base.py` — Dataclasses e classe base
- [x] `nvd_checker/scanner/python_parser.py` — Parser Python
- [x] `nvd_checker/scanner/node_parser.py` — Parser Node.js
- [x] `nvd_checker/scanner/go_parser.py` — Parser Go
- [x] `nvd_checker/scanner/java_parser.py` — Parser Java
- [x] `nvd_checker/scanner/ruby_parser.py` — Parser Ruby
- [x] `nvd_checker/scanner/detector.py` — Auto-detecção

## Cliente NVD API
- [x] `nvd_checker/nvd/models.py` — Dataclasses para CVE
- [x] `nvd_checker/nvd/client.py` — Cliente HTTP NVD API 2.0
- [x] `nvd_checker/nvd/matcher.py` — Matching dependência → CVE

## Relatórios
- [x] `nvd_checker/report/advisor.py` — Dicas de correção
- [x] `nvd_checker/report/generator.py` — Gerador de relatórios
- [x] `nvd_checker/report/templates/report.html` — Template HTML

## CLI
- [x] `nvd_checker/cli.py` — Comandos CLI
- [x] `nvd_checker/utils.py` — Utilitários

## Testes
- [x] `tests/test_scanner.py`
- [x] `tests/test_nvd_client.py`
- [x] `tests/test_matcher.py`
- [x] `tests/test_report.py`

## Verificação
- [x] Instalar e testar CLI
- [x] Rodar testes — **29/29 passed ✅**

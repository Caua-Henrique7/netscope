# netscope

Ferramenta de análise de redes em linha de comando, com foco em reconhecimento para testes autorizados.

> ⚠️ Use apenas em redes e sistemas que você possui ou tem autorização por escrito para testar.

## Status

Em desenvolvimento — versão 0.1.0.

## Requisitos

- Python 3.11 ou superior

## Instalação

```bash
git clone git@github.com:Caua-Henrique7/netscope.git
cd netscope
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Uso

```bash
# Escaneia as portas mais comuns de um host
netscope scan 192.168.1.10

# Uma rede inteira, portas específicas
netscope scan 192.168.1.0/24 -p 22,80,443

# Todas as portas, sem busca de DNS
netscope scan 192.168.1.10 -p full -n
```

Principais opções:

| Opção | O que faz |
|---|---|
| `-p top\|full\|22,80,8000-8100` | portas a escanear (padrão: lista comum) |
| `-Pn` | pula a descoberta e trata todo endereço como ativo |
| `--rate N` | no máximo N conexões por segundo |
| `-c`, `--timeout` | concorrência e tempo limite |
| `-n` | sem busca reversa de DNS |
| `--allow-public` | permite escanear IP público (somente com autorização) |

Veja todas com `netscope scan -h`.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest
```

## Licença

MIT. Veja o arquivo [LICENSE](LICENSE).
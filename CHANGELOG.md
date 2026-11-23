# Changelog

Todas as mudanças importantes do netscope ficam registradas aqui.

## [Não lançado]

### Adicionado
- Estrutura inicial do projeto (pacote, empacotamento, licença).
- Parser de alvos: IP, CIDR, range e hostname, com lista de exclusão e limite de segurança.
- Parser de portas: `top`, `full`, listas e ranges.
- Trava de escopo: bloqueia IP público sem `--allow-public`.
- Utilidades: cores no terminal, controle de ritmo e barra de progresso.
- Motor de varredura assíncrono: descoberta de hosts e scan de portas TCP, com busca reversa de DNS.
- CLI `netscope scan`, com saída colorida no terminal.
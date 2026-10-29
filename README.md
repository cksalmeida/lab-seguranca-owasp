# Laboratório Prático: O Caso da API Solidária Vulnerável

Auditoria de segurança da API de arrecadação do Hub Solidário. O objetivo do
trabalho é provar, por meio de testes automatizados, duas falhas de injeção
presentes na primeira versão do código e, em seguida, refatorar a aplicação até
alcançar conformidade com as diretrizes da OWASP.

## Vulnerabilidades investigadas

- **SQL Injection (OWASP A03)** — concatenação de parâmetros diretamente na
  consulta SQL, permitindo burlar a autenticação e extrair dados de outras
  tabelas via `UNION SELECT`.
- **Cross-Site Scripting armazenado (OWASP A03)** — persistência e reflexão de
  conteúdo HTML bruto, sem sanitização, enviado por usuários.

Para cada falha há duas rotas: uma vulnerável (`/vulneravel/...`), mantida apenas
para fins didáticos, e uma corrigida (`/seguro/...`).

## Estrutura do projeto

```
lab-seguranca-owasp/
├── main.py                   # API FastAPI (rotas vulneráveis e seguras)
├── pyproject.toml            # dependências e configuração do pytest
├── README.md
└── tests/
    └── test_seguranca.py     # suíte de testes de segurança (padrão AAA)
```

## Como executar

Pré-requisito: [uv](https://github.com/astral-sh/uv) instalado.

Instalar as dependências:

```
uv sync
```

Rodar a suíte de testes:

```
uv run pytest -v
```

Subir a API para inspeção manual em `http://127.0.0.1:8000/docs`:

```
uv run uvicorn main:app --reload
```

## Medidas de correção aplicadas

| Falha              | Rota vulnerável                | Correção na rota segura                                   |
|--------------------|--------------------------------|----------------------------------------------------------|
| SQL Injection      | f-string na query              | consultas parametrizadas (prepared statements com `?`)   |
| SQL Injection UNION| `LIKE '%...%'` concatenado     | `LIKE ?` com o curinga montado no parâmetro              |
| XSS armazenado     | conteúdo HTML refletido cru    | `html.escape()` antes de persistir e refletir           |

Nas rotas seguras, o mecanismo do banco trata os valores exclusivamente como
literais, e os caracteres `<`, `>`, `&` e `"` são convertidos em entidades HTML.
Tentativas de exploração resultam em `401 Unauthorized` (login) ou em resultado
vazio (busca), sem expor rastros de pilha.

## Suíte de testes

Os testes seguem o padrão Arrange–Act–Assert e usam o marcador
`@pytest.mark.security`, registrado no `pyproject.toml`. São oito casos, divididos
em auditoria ofensiva (prova a falha na rota vulnerável) e defensiva (comprova a
mitigação na rota segura):

1. SQL Injection no login — burla de autenticação.
2. SQL Injection no login — bloqueio pela rota segura.
3. XSS em comentário — tag `<script>` refletida intacta.
4. XSS em comentário — sanitização na rota segura.
5. SQL Injection `UNION SELECT` — extração de credenciais na busca.
6. SQL Injection `UNION SELECT` — bloqueio pela busca segura.
7. XSS via `onerror` — burla de filtro ingênuo que remove apenas a palavra `script`.
8. XSS via `onerror` — neutralização pela sanitização.

Para filtrar apenas os testes de segurança:

```
uv run pytest -v -m security
```

## Observações de implementação

- O modelo de login usa `str` no campo de e-mail (em vez de `EmailStr`). Isso é
  intencional: os payloads de ataque não são e-mails válidos e seriam rejeitados
  na validação antes de alcançar a consulta, o que impediria a demonstração da
  falha.
- O banco é um SQLite em memória, recriado a cada inicialização, com dados de
  teste pré-carregados. Não há persistência entre execuções.

## Checklist de autoavaliação

- [x] Nenhuma consulta concatena strings diretamente nas rotas seguras.
- [x] Login e busca seguros usam consultas parametrizadas.
- [x] Conteúdo textual do usuário é codificado com `html.escape()`.
- [x] Testes seguem o padrão AAA com o marcador `@pytest.mark.security`.
- [x] Cargas hostis retornam erros semânticos, sem vazar stack traces.
- [x] Suíte executada com `uv run pytest` — 8 testes aprovados.

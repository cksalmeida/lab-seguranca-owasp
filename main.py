"""
API do Hub Solidário com demonstração comparativa de vulnerabilidades e correções.
"""

import html
import sqlite3
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Hub Solidario - Laboratorio de Seguranca")


def obter_banco():
    """Gera conexão com banco SQLite em memória com dados pré-carregados."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comentarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            autor TEXT NOT NULL,
            conteudo TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campanhas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            meta TEXT NOT NULL
        )
    """)
    # Inserção de dados iniciais de teste
    cursor.execute("""
        INSERT INTO usuarios (nome, email, senha, is_admin)
        VALUES
            ('Administrador', 'admin@hubsolidario.org', 'segredo_admin_123', 1),
            ('Voluntario Lucas', 'lucas@voluntariado.org', 'senha_lucas_456', 0)
    """)
    cursor.execute("""
        INSERT INTO campanhas (titulo, meta)
        VALUES
            ('Agasalho Solidario', '10000'),
            ('Cesta Basica de Natal', '25000')
    """)
    conn.commit()
    return conn


db = obter_banco()


class RequisicaoLogin(BaseModel):
    email: str
    senha: str


class RequisicaoComentario(BaseModel):
    autor: str
    conteudo: str


# ==============================================================================
# ENDPOINTS INTENCIONALMENTE VULNERAVEIS (GERADOS POR IA SEM REVISÃO)
# ==============================================================================

@app.post("/vulneravel/login")
def login_vulneravel(dados: RequisicaoLogin):
    """
    VULNERABILIDADE: SQL Injection (OWASP A03).
    A IA concatenou os parâmetros diretamente na consulta SQL via f-string.
    """
    cursor = db.cursor()
    query = f"SELECT id, nome, email, is_admin FROM usuarios WHERE email = '{dados.email}' AND senha = '{dados.senha}'"
    cursor.execute(query)
    usuario = cursor.fetchone()

    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais invalidas"
        )

    return {
        "id": usuario[0],
        "nome": usuario[1],
        "email": usuario[2],
        "is_admin": bool(usuario[3]),
        "status": "Autenticado com sucesso"
    }


@app.post("/vulneravel/comentarios")
def comentar_vulneravel(dados: RequisicaoComentario):
    """
    VULNERABILIDADE: Stored XSS (OWASP A03 / LLM02).
    A IA persistiu e refletiu conteúdo HTML bruto sem qualquer sanitização.
    """
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)",
        (dados.autor, dados.conteudo)
    )
    db.commit()

    return {
        "autor": dados.autor,
        "conteudo": dados.conteudo,
        "aviso": "Comentario registrado sem higienizacao"
    }


@app.get("/vulneravel/campanhas/buscar")
def buscar_campanhas_vulneravel(termo: str):
    """
    VULNERABILIDADE: SQL Injection via UNION SELECT (OWASP A03).
    A IA concatenou o termo de busca diretamente na cláusula LIKE.
    """
    cursor = db.cursor()
    query = f"SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE '%{termo}%'"
    cursor.execute(query)
    resultados = cursor.fetchall()

    return {
        "termo": termo,
        "resultados": [
            {"id": linha[0], "titulo": linha[1], "meta": linha[2]}
            for linha in resultados
        ]
    }


# ==============================================================================
# ENDPOINTS SEGUROS (REFATORADOS EM CONFORMIDADE COM A OWASP)
# ==============================================================================

@app.post("/seguro/login")
def login_seguro(dados: RequisicaoLogin):
    """
    PROTEÇÃO: Consultas Parametrizadas (Prepared Statements).
    O mecanismo de banco trata os parâmetros exclusivamente como literais.
    """
    cursor = db.cursor()
    query = "SELECT id, nome, email, is_admin FROM usuarios WHERE email = ? AND senha = ?"
    cursor.execute(query, (dados.email, dados.senha))
    usuario = cursor.fetchone()

    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais invalidas"
        )

    return {
        "id": usuario[0],
        "nome": usuario[1],
        "email": usuario[2],
        "is_admin": bool(usuario[3]),
        "status": "Autenticado com sucesso"
    }


@app.post("/seguro/comentarios")
def comentar_seguro(dados: RequisicaoComentario):
    """
    PROTEÇÃO: Sanitização com html.escape() e validação estrutural.
    Caracteres especiais como <, >, &, " sao convertidos em entidades seguras.
    """
    autor_seguro = html.escape(dados.autor.strip())
    conteudo_seguro = html.escape(dados.conteudo.strip())

    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)",
        (autor_seguro, conteudo_seguro)
    )
    db.commit()

    return {
        "autor": autor_seguro,
        "conteudo": conteudo_seguro,
        "aviso": "Comentario higienizado com sucesso"
    }


@app.get("/seguro/campanhas/buscar")
def buscar_campanhas_seguro(termo: str):
    """
    PROTEÇÃO: Consulta Parametrizada com LIKE ?.
    O curinga é montado no parâmetro, nunca concatenado na string SQL.
    """
    cursor = db.cursor()
    query = "SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE ?"
    cursor.execute(query, (f"%{termo}%",))
    resultados = cursor.fetchall()

    return {
        "termo": termo,
        "resultados": [
            {"id": linha[0], "titulo": linha[1], "meta": linha[2]}
            for linha in resultados
        ]
    }

#!/usr/bin/env python3
"""Valida lista.json: schema, regras do HA Security Auditor e (opcional) a assinatura.

Uso (na raiz do repositório):

    python3 scripts/validar.py                 # formato e regras (o que o CI roda em PRs)
    python3 scripts/validar.py --assinatura    # também exige lista.json.sig válida (CI na main)

As regras são as mesmas que o add-on aplica ao ler a lista; um item que passa aqui é aceito lá.
A checagem de assinatura usa as chaves públicas de chaves.json e serve para pegar esquecimentos
(lista alterada sem assinar de novo). A proteção de verdade é a chave embutida no add-on.

Requer: pip install -r requirements-ci.txt
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
NIVEIS = {"critica", "alta", "media", "aviso"}
MAX_BYTES = 2 * 1024 * 1024


def erros_de_formato(doc: object) -> list[str]:
    from jsonschema import Draft202012Validator

    schema = json.loads((RAIZ / "schema" / "lista.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        onde = "/".join(str(p) for p in err.absolute_path) or "(raiz)"
        out.append(f"{onde}: {err.message}")
    return out


def erros_de_regras(doc: dict) -> list[str]:
    """Regras que o schema não expressa (iguais às do add-on)."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet

    out = []
    vistos: dict[str, int] = {}
    for n, item in enumerate(doc.get("itens") or [], start=1):
        if not isinstance(item, dict):
            continue
        ident = item.get("id")
        if ident in vistos:
            out.append(f"itens/{n - 1}: id '{ident}' repetido (já usado no item {vistos[ident]})")
        vistos.setdefault(ident, n)
        versoes = item.get("versoes") or ""
        if versoes:
            try:
                SpecifierSet(versoes)
            except InvalidSpecifier:
                out.append(f"itens/{n - 1}: 'versoes' inválido ({versoes!r}); use o formato do pip, ex.: \"<1.4.2\"")
        nome = item.get("nome")
        if isinstance(nome, str) and set(nome) <= {"*", "?"}:
            out.append(f"itens/{n - 1}: 'nome' não pode ser só curinga")
        for campo in ("motivo", "nome", "github", "imagem"):
            valor = item.get(campo)
            if isinstance(valor, str) and any(ord(c) < 32 for c in valor):
                out.append(f"itens/{n - 1}: '{campo}' tem caracteres de controle")
    return out


def erro_de_assinatura(dados: bytes) -> str | None:
    import hashlib

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        sig = json.loads((RAIZ / "lista.json.sig").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return "lista.json.sig não existe; rode python3 scripts/assinar.py"
    except ValueError:
        return "lista.json.sig não é um JSON válido"
    chaves = json.loads((RAIZ / "chaves.json").read_text(encoding="utf-8"))
    kid = sig.get("chave")
    if sig.get("algoritmo") != "ed25519" or kid not in chaves:
        return f"assinatura com algoritmo ou chave desconhecida ({kid})"
    pub = base64.b64decode(chaves[kid])
    if hashlib.sha256(pub).hexdigest()[:16] != kid:
        return f"chaves.json: o id {kid} não corresponde à chave"
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(sig.get("assinatura", "")), dados)
    except (InvalidSignature, ValueError):
        return "assinatura não confere: lista.json foi alterado depois de assinado; rode python3 scripts/assinar.py"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--assinatura", action="store_true", help="exige lista.json.sig válida")
    args = ap.parse_args()

    caminho = RAIZ / "lista.json"
    dados = caminho.read_bytes()
    problemas: list[str] = []
    if len(dados) > MAX_BYTES:
        problemas.append(f"lista.json passa de {MAX_BYTES // 1024 // 1024} MB")
    if b"\r\n" in dados:
        problemas.append("lista.json tem quebras de linha CRLF; use LF")
    try:
        doc = json.loads(dados.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        print(f"::error file=lista.json::JSON inválido: {err}")
        return 1
    problemas += erros_de_formato(doc)
    if isinstance(doc, dict):
        problemas += erros_de_regras(doc)
    if args.assinatura and (erro := erro_de_assinatura(dados)):
        problemas.append(erro)

    for p in problemas:
        # Formato de anotação do GitHub Actions (aparece no PR); no terminal é só uma linha.
        print(f"::error file=lista.json::{p}")
    itens = len(doc.get("itens") or []) if isinstance(doc, dict) else 0
    if problemas:
        print(f"{len(problemas)} problema(s) encontrado(s).", file=sys.stderr)
        return 1
    print(f"lista.json OK: {itens} item(ns){', assinatura válida' if args.assinatura else ''}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

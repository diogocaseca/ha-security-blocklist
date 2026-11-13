#!/usr/bin/env python3
"""Assina lista.json com a chave Ed25519 do mantenedor e grava lista.json.sig.

Uso (na raiz do repositório):

    python3 scripts/assinar.py                 # chave em ~/.config/ha-security-blocklist/assinatura.key
    python3 scripts/assinar.py --chave outra.key

Antes de assinar, atualiza "atualizado_em" para a data de hoje (UTC) e confere o básico do
formato. O HA Security Auditor só usa a lista se a assinatura bater com uma das chaves
públicas embutidas nele e recusa listas mais antigas que a que já tem.

Requer: pip install -r requirements-ci.txt
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RAIZ = Path(__file__).resolve().parent.parent
CHAVE_PADRAO = Path.home() / ".config" / "ha-security-blocklist" / "assinatura.key"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--chave", type=Path, default=CHAVE_PADRAO, help="chave privada Ed25519 (PEM)")
    ap.add_argument("--lista", type=Path, default=RAIZ / "lista.json")
    args = ap.parse_args()

    doc = json.loads(args.lista.read_text(encoding="utf-8"))
    if doc.get("versao") != 1 or not isinstance(doc.get("itens"), list):
        print("lista.json fora do formato (versao 1 com 'itens')", file=sys.stderr)
        return 1
    # Mesmas regras do CI: não assina uma lista que o add-on recusaria.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from validar import erros_de_formato, erros_de_regras

    problemas = erros_de_formato(doc) + erros_de_regras(doc)
    if problemas:
        for prob in problemas:
            print(f"- {prob}", file=sys.stderr)
        print("Corrija a lista antes de assinar.", file=sys.stderr)
        return 1
    doc["atualizado_em"] = datetime.now(UTC).date().isoformat()
    ordered = {"versao": doc["versao"], "atualizado_em": doc["atualizado_em"], "itens": doc["itens"]}
    data = (json.dumps(ordered, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    args.lista.write_bytes(data)

    key = serialization.load_pem_private_key(args.chave.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print("a chave não é Ed25519", file=sys.stderr)
        return 1
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = {
        "versao": 1,
        "algoritmo": "ed25519",
        "chave": hashlib.sha256(pub).hexdigest()[:16],
        "assinatura": base64.b64encode(key.sign(data)).decode(),
    }
    (args.lista.parent / "lista.json.sig").write_text(json.dumps(sig, indent=2) + "\n", encoding="utf-8")
    print(f"Assinada: {len(doc['itens'])} item(ns), atualizado_em {doc['atualizado_em']}, chave {sig['chave']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

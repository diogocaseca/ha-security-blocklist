#!/usr/bin/env python3
"""Importa para lista.json as listas que o HACS e o Home Assistant já mantêm.

Fontes:
- HACS: https://github.com/hacs/default/blob/master/removed (repositórios removidos ou
  bloqueados da lista padrão do HACS);
- Home Assistant: BLOCKED_CUSTOM_INTEGRATIONS em homeassistant/loader.py (versões de
  integrações customizadas que o próprio HA se recusa a carregar), na branch master (versão
  publicada).

Os itens importados têm "fonte": "hacs" ou "home-assistant" e são substituídos a cada
importação; itens da comunidade não são tocados. O loader.py é lido só pela árvore sintática
(ast): nada do que é baixado é executado.

Uso (na raiz do repositório):

    .venv/bin/python scripts/importar.py              # atualiza lista.json
    .venv/bin/python scripts/importar.py --verificar  # só diz se há mudanças (saída 1 se houver)

Depois de importar, revise o diff e assine com scripts/assinar.py.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
HACS_URL = "https://raw.githubusercontent.com/hacs/default/master/removed"
HACS_PAGINA = "https://github.com/hacs/default/blob/master/removed"
HA_URL = "https://raw.githubusercontent.com/home-assistant/core/master/homeassistant/loader.py"
HA_PAGINA = "https://github.com/home-assistant/core/blob/master/homeassistant/loader.py"
FONTES = ("hacs", "home-assistant")
MAX_BYTES = 5 * 1024 * 1024

_GITHUB = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_DOMINIO = re.compile(r"^[a-z0-9_]{1,60}$")
_URL = re.compile(r"https://[^\s)>\]\"']+")
_ABANDONADO = re.compile(r"abandon|archiv|no longer maintained|not maintained|unmaintained", re.I)


def baixar(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ha-security-blocklist-importador"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - URLs fixas https
        dados = resp.read(MAX_BYTES + 1)
    if len(dados) > MAX_BYTES:
        raise SystemExit(f"{url} é grande demais")
    return dados


def _limpa(texto: str, limite: int = 400) -> str:
    texto = " ".join(str(texto).split())
    return texto if len(texto) <= limite else texto[: limite - 1] + "…"


def _id(prefixo: str, chave: str) -> str:
    legivel = re.sub(r"[^a-z0-9]+", "-", chave.lower()).strip("-")[:24].strip("-")
    return f"{prefixo}-{legivel}-{hashlib.sha256(chave.lower().encode()).hexdigest()[:6]}"


# --- HACS ----------------------------------------------------------------------------------------


def itens_hacs(dados: bytes) -> tuple[list[dict], list[str]]:
    itens: dict[str, dict] = {}
    avisos: list[str] = []
    ordem = {"critica": 3, "alta": 2, "media": 1, "aviso": 0}
    for raw in json.loads(dados):
        repo = str(raw.get("repository", "")).strip()
        if not _GITHUB.match(repo):
            avisos.append(f"HACS: repositório ignorado ({repo!r})")
            continue
        tipo = str(raw.get("removal_type", "")).strip()
        motivo_original = _limpa(raw.get("reason") or "")
        if tipo.lower() == "critical":
            nivel, categoria = "critica", "malicioso"
            motivo = f"Removido do HACS como problema crítico de segurança: {motivo_original or 'sem detalhes'}"
        elif tipo.lower() == "blacklist":
            nivel, categoria = "media", "removido"
            motivo = ("Bloqueado (blacklist) na lista padrão do HACS"
                      + (f": {motivo_original}" if motivo_original else "; o HACS não publica o motivo."))
        else:
            # Tipos variados ("remove", "removed", "archived", "deprecated"...); alguns trazem o motivo no tipo.
            motivo_original = motivo_original or (_limpa(tipo) if len(tipo) > 12 else "")
            nivel = "aviso"
            categoria = "abandonado" if _ABANDONADO.search(f"{tipo} {motivo_original}") else "removido"
            motivo = "Removido da lista padrão do HACS" + (f": {motivo_original}" if motivo_original else ".")
        link = str(raw.get("link") or "")
        item = {
            "id": _id("hacs", repo),
            "github": repo,
            "nivel": nivel,
            "categoria": categoria,
            "motivo": _limpa(motivo, 500),
            "evidencias": [link] if link.startswith("https://") and " " not in link else [HACS_PAGINA],
            "fonte": "hacs",
        }
        atual = itens.get(repo.lower())
        if atual is None or ordem[nivel] > ordem[atual["nivel"]]:
            itens[repo.lower()] = item
    return sorted(itens.values(), key=lambda i: i["id"]), avisos


# --- Home Assistant ---------------------------------------------------------------------------------


def _texto(no: ast.AST) -> str | None:
    if isinstance(no, ast.Constant) and isinstance(no.value, str):
        return no.value
    return None


def _versao(no: ast.AST) -> str | None:
    if isinstance(no, ast.Constant) and no.value is None:
        return None
    if isinstance(no, ast.Call) and no.args:  # AwesomeVersion("1.2.3")
        return _texto(no.args[0])
    return None


def itens_ha(dados: bytes) -> tuple[list[dict], list[str]]:
    fonte = dados.decode("utf-8")
    linhas = fonte.splitlines()
    arvore = ast.parse(fonte)
    dicionario = None
    for no in ast.walk(arvore):
        alvo = no.target if isinstance(no, ast.AnnAssign) else (no.targets[0] if isinstance(no, ast.Assign) else None)
        if isinstance(alvo, ast.Name) and alvo.id == "BLOCKED_CUSTOM_INTEGRATIONS" and isinstance(no.value, ast.Dict):
            dicionario = no.value
            break
    if dicionario is None:
        raise SystemExit("BLOCKED_CUSTOM_INTEGRATIONS não encontrado no loader.py (o formato mudou?)")

    from packaging.version import InvalidVersion, Version

    itens, avisos = [], []
    for chave, valor in zip(dicionario.keys, dicionario.values, strict=True):
        dominio = _texto(chave) if chave is not None else None
        if not dominio or not _DOMINIO.match(dominio) or not isinstance(valor, ast.Call):
            avisos.append(f"HA: entrada ignorada na linha {getattr(chave, 'lineno', '?')}")
            continue
        args = list(valor.args)
        kw = {k.arg: k.value for k in valor.keywords}
        versao = _versao(kw.get("lowest_good_version", args[0] if args else ast.Constant(None)))
        motivo = _texto(kw.get("reason", args[1] if len(args) > 1 else ast.Constant(""))) or ""
        substituto = _texto(kw["replaced_by"]) if "replaced_by" in kw else None
        # Links nos comentários logo acima da entrada ("Added in ... because of <url>").
        links, n = [], chave.lineno - 2
        while n >= 0 and linhas[n].strip().startswith("#"):
            links = _URL.findall(linhas[n]) + links
            n -= 1
        if versao:
            try:
                Version(versao)
            except InvalidVersion:
                avisos.append(f"HA: versão '{versao}' de {dominio} não comparável; vale para todas")
                versao = None
        item = {
            "id": f"ha-{dominio}"[:40],
            "tipo": "integracao",
            "nome": dominio,
            "nivel": "aviso" if substituto else "alta",
            "categoria": "removido" if substituto else "incompativel",
            "motivo": _limpa(
                f"Substituída pela integração nativa '{substituto}': {motivo}." if substituto
                else f"O Home Assistant não carrega esta versão: {motivo}.", 500),
            "evidencias": (links or [HA_PAGINA])[:10],
            "fonte": "home-assistant",
        }
        if versao:
            item["versoes"] = f"<{versao}"
        itens.append(item)
    return sorted(itens, key=lambda i: i["id"]), avisos


# --- Junção -------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verificar", action="store_true", help="não grava; saída 1 se houver mudanças")
    args = ap.parse_args()

    caminho = RAIZ / "lista.json"
    doc = json.loads(caminho.read_text(encoding="utf-8"))
    antigos = {i["id"]: i for i in doc["itens"]}
    hoje = datetime.now(UTC).date().isoformat()

    hacs, avisos_hacs = itens_hacs(baixar(HACS_URL))
    ha, avisos_ha = itens_ha(baixar(HA_URL))
    for aviso in avisos_hacs + avisos_ha:
        print(f"aviso: {aviso}", file=sys.stderr)

    importados = hacs + ha
    for item in importados:
        # Mantém a data em que o item entrou pela primeira vez.
        item["adicionado_em"] = antigos.get(item["id"], {}).get("adicionado_em", hoje)
    ids_importados = {i["id"] for i in importados}
    colisoes = [i["id"] for i in doc["itens"] if i.get("fonte") not in FONTES and i["id"] in ids_importados]
    if colisoes:
        print(f"ids da comunidade colidem com importados: {colisoes}", file=sys.stderr)
        return 2
    comunidade = [i for i in doc["itens"] if i.get("fonte") not in FONTES]
    novos = comunidade + importados

    def chave(i: dict) -> str:
        return json.dumps(i, sort_keys=True, ensure_ascii=False)

    antes = {chave(i) for i in doc["itens"] if i.get("fonte") in FONTES}
    depois = {chave(i) for i in importados}
    ids_antes = {i["id"] for i in doc["itens"] if i.get("fonte") in FONTES}
    entraram = len(ids_importados - ids_antes)
    sairam = len(ids_antes - ids_importados)
    mudaram = len({json.loads(c)["id"] for c in depois - antes}) - entraram
    print(f"HACS: {len(hacs)} · Home Assistant: {len(ha)} · comunidade: {len(comunidade)}")
    print(f"Mudanças: {entraram} novos, {sairam} removidos, {mudaram} alterados")

    if args.verificar:
        return 1 if antes != depois else 0
    if antes != depois:
        doc["itens"] = novos
        caminho.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("lista.json atualizado. Revise o diff e rode scripts/assinar.py.")
    else:
        print("Nada mudou.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

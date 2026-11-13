# Community blocklist — HA Security Auditor

*[Versão em português](README.pt-BR.md)*

List of Home Assistant integrations, cards and add-ons **reported** as malicious, compromised,
vulnerable, abandoned or with undisclosed telemetry. It is used by
[HA Security Auditor](https://github.com/diogocaseca/ha-security-auditor), which shows a warning
in the components table when something installed appears here.

> Each item is a **report backed by evidence**, not a verdict. The auditor always shows the reason
> and the links so the user can decide.

The field names and values in `lista.json` are in Portuguese (for example `nivel: critica`); they
are listed in English in [Format](#format-versao-1).

## How the auditor uses the list

- It downloads the whole `lista.json` file and compares it **locally** with what is installed.
  Nothing about anyone's installation is sent here.
- The list only **adds warnings**: it does not allow, hide or change what the auditor checks.
- Match by GitHub repository or by image = strong warning. By name only = "possible match", one
  severity level lower (except Home Assistant items, since HA blocks by integration domain).
- Add-ons fetch the list on each scan, at most every 6 hours.

## How to add an item

**Just want to flag something in your own installation?** Use the [personal list](#personal-list):
it needs neither this repository nor a signature.

**Want to suggest it for everyone?** Open an issue with the *Relatar um componente* (report a
component) form or a Pull Request (see [How to contribute](#how-to-contribute)). The maintainer
reviews and publishes it.

### Maintainer step by step

The first time, set up the environment at the repository root:

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-ci.txt
```

The private key must be at `~/.config/ha-security-blocklist/assinatura.key` (or pass `--chave` to
the script).

1. **Find out how to identify the component.** In the auditor's components table, each row shows
   the name (use it in `nome`) and the repository (`repositorio: owner/repo`, use it in `github`).
   Prefer `github`; for add-ons, `imagem` is strong too.
2. **Add the item** inside `itens` in `lista.json`, with a new `id` and at least one piece of
   evidence. Leave `fonte` as `comunidade` (or omit it); `hacs` and `home-assistant` are rebuilt
   by the importer and any manual edit to them is lost.

   ```json
   {
     "id": "2026-001",
     "github": "owner/repository",
     "versoes": "<1.4.2",
     "nivel": "critica",
     "categoria": "comprometido",
     "motivo": "Version 1.4.1 was published by a hijacked account and sends the HA token elsewhere.",
     "evidencias": ["https://github.com/owner/repository/issues/123"],
     "fonte": "comunidade"
   }
   ```

3. **Sign.** The script validates the list with the same rules as the CI and does not sign if
   there is an error; it also updates `atualizado_em`.

   ```bash
   .venv/bin/python scripts/assinar.py
   ```

4. **Commit both files together and push.** Without the new `lista.json.sig`, the CI fails on
   `main` and the add-ons reject the list (they keep the previous version).

   ```bash
   git add lista.json lista.json.sig && git commit -m "Add 2026-001" && git push
   ```

5. **Check the CI** in the *Actions* tab ("Validar lista" green). Each add-on picks up the new
   list on the first scan after 6 hours have passed since the last fetch (restarting the add-on
   does not help, because the time of the last fetch is saved).

To **fix** an item, edit it (for example, narrow `versoes` when a fix is released) and repeat
steps 3 and 4. To **remove** one, delete the item and repeat steps 3 and 4.

To accept someone else's **Pull Request**: merge it, update your copy (`git pull`) and run steps
3 and 4 (contributors do not have the key, so the PR arrives without a new signature).

## Format (`versao: 1`)

```json
{
  "versao": 1,
  "atualizado_em": "2026-11-13",
  "itens": [
    {
      "id": "2026-001",
      "tipo": "integracao",
      "github": "owner/repository",
      "nome": "integration_domain",
      "versoes": "<1.4.2",
      "nivel": "critica",
      "categoria": "comprometido",
      "motivo": "Version 1.4.1 was published by a hijacked account and sends the HA token elsewhere.",
      "evidencias": ["https://github.com/owner/repository/issues/123"],
      "adicionado_em": "2026-11-13"
    }
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier, e.g. `2026-001`. |
| `tipo` (type) | no | `integracao` (integration), `frontend` (cards in `www/`) or `addon`. Empty = any type. |
| `github` | one of the three | `owner/repository`. The most reliable match. |
| `nome` (name) | one of the three | Integration domain, card folder or add-on slug. Accepts `*` and `?`, but not a wildcard alone. |
| `imagem` (image) | one of the three | Add-on image, e.g. `ghcr.io/owner/{arch}-addon-x` (`{arch}` matches any architecture). |
| `versoes` (versions) | no | Affected range in pip format, e.g. `<1.4.2` or `>=1.0,<1.2`. Empty = all. |
| `nivel` (level) | yes | `critica` (critical), `alta` (high), `media` (medium) or `aviso` (warning). |
| `categoria` (category) | yes | `malicioso` (malicious), `comprometido` (compromised), `vulneravel` (vulnerable), `abandonado` (abandoned), `telemetria` (telemetry), `removido` (removed or blocked from an official store) or `incompativel` (incompatible: a version HA itself blocks). |
| `fonte` (source) | no | `comunidade` (community, the default for reports), `hacs` or `home-assistant` (imported items; do not edit by hand). |
| `motivo` (reason) | yes | One or two objective sentences (up to 500 characters). |
| `evidencias` (evidence) | yes | 1 to 10 `https://` links (issue, analysis, CVE, author's notice). Optional in the personal list. |
| `adicionado_em` (added on) | no | Date `YYYY-MM-DD`. |

The full format is in [`schema/lista.schema.json`](schema/lista.schema.json).

## Imported sources

Besides community reports, the list includes what HACS and Home Assistant already publish:

| Source | What goes in | Level |
|---|---|---|
| [HACS — `removed`](https://github.com/hacs/default/blob/master/removed) | Repositories removed from the HACS default list | `critica` (critical), `media` (blacklist), `aviso` (removed/archived) |
| [Home Assistant — `BLOCKED_CUSTOM_INTEGRATIONS`](https://github.com/home-assistant/core/blob/master/homeassistant/loader.py) | Custom integration versions that HA refuses to load | `alta` (or `aviso` when replaced by a built-in one) |

Imported items have `fonte` `hacs` or `home-assistant` and are rebuilt on each import
(`scripts/importar.py`); their reasons stay in the source's original language. Every Monday the
`fontes.yml` workflow checks whether the sources changed and fails (with an e-mail notice) when
there is something to import. The data belongs to the respective projects: HACS (MIT license) and
Home Assistant (Apache 2.0).

To update:

```bash
.venv/bin/python scripts/importar.py
```
```bash
.venv/bin/python scripts/assinar.py
```

## Signature

The auditor only uses the list if `lista.json.sig` is a valid **Ed25519** signature of
`lista.json`, made with the maintainer's key. The public key is embedded in the add-on, so whoever
manages to change this repository cannot publish items without the private key. The auditor also
rejects a list whose `atualizado_em` is older than the one it already has.

To publish a change, the maintainer runs, at the repository root:

```bash
.venv/bin/python scripts/assinar.py
```

The script validates the list with the same rules as the CI (and does not sign if there is a
problem), updates `atualizado_em` and writes `lista.json.sig`. `lista.json` and `lista.json.sig`
must go **in the same commit**. `.gitattributes` keeps git from changing line endings, because the
signature covers the file's exact bytes.

## Automatic validation

Every PR goes through GitHub Actions (`.github/workflows/validar.yml`), which runs
`scripts/validar.py`: schema (`schema/lista.schema.json`), unique ids, valid `versoes` range,
`https://` links only and a `nome` that is not just a wildcard, the same rules as the add-on. On
`main` it also requires `lista.json.sig` to match a key in `chaves.json`, to catch changes that
went live without a signature.

To validate locally:

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-ci.txt
```
```bash
.venv/bin/python scripts/validar.py
```

## How to contribute

1. Open a Pull Request that changes only `lista.json`, with **one item per PR** (the maintainer
   signs it after approving).
2. Include at least one public, verifiable piece of evidence. Reports without evidence are not
   accepted.
3. Prefer `github` over `nome`, and narrow `versoes` when the problem has already been fixed.
4. Describe facts ("sends the token to X"), not accusations.

Fixed items can be updated with a `versoes` range instead of being removed.

## Personal list

Auditor users can also keep their own list, added to this one, which applies only to their own
installation and needs neither a signature nor evidence. It is managed in the add-on's interface
(version 0.12.0 or newer):

1. **Blocklist** tab → **Add item…**, or **Add to blocklist…** on a component's screen (it comes
   pre-filled with the type, GitHub and name).
2. Choose the level and category, write the reason and save.
3. Click **Scan now**: the component gets the **Blocklist** badge.

The items are stored in the add-on's database and can be edited and removed from the same tab.
There is no need to create a folder or file in `/config` (the `lista_negra.json` file from earlier
versions is no longer read).

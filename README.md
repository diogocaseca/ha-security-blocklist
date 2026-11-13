# Lista negra comunitária — HA Security Auditor

Lista de integrações, cards e add-ons do Home Assistant **reportados** como maliciosos,
comprometidos, vulneráveis, abandonados ou com telemetria não declarada. É usada pelo
[HA Security Auditor](https://github.com/diogocaseca/ha-security-auditor), que mostra um aviso
na tabela de componentes quando algo instalado aparece aqui.

> Cada item é um **relato com evidências**, não um veredito. O auditor sempre mostra o motivo e
> os links para quem usa decidir.

## Como o auditor usa a lista

- Baixa o arquivo `lista.json` inteiro e compara **localmente** com o que está instalado. Nada
  sobre a instalação de ninguém é enviado para cá.
- A lista só **acrescenta avisos**: não libera, não esconde e não muda o que o auditor verifica.
- Correspondência pelo repositório do GitHub ou pela imagem = aviso forte. Só pelo nome =
  "possível correspondência", um nível de severidade abaixo (exceto itens do Home Assistant,
  que bloqueia pelo domínio da integração).
- Os add-ons buscam a lista a cada varredura, no máximo a cada 6 horas.

## Como adicionar um item

**Quer só marcar algo na sua instalação?** Use a [lista pessoal](#lista-pessoal): não precisa
deste repositório nem de assinatura.

**Quer sugerir para todos?** Abra uma issue pelo formulário *Relatar um componente* ou um Pull
Request (veja [Como contribuir](#como-contribuir)). O mantenedor revisa e publica.

### Passo a passo do mantenedor

Na primeira vez, prepare o ambiente na raiz do repositório:

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-ci.txt
```

A chave privada precisa estar em `~/.config/ha-security-blocklist/assinatura.key` (ou passe
`--chave` para o script).

1. **Descubra como identificar o componente.** Na tabela de componentes do auditor, cada linha
   mostra o nome (use em `nome`) e o repositório (`repositorio: dono/repo`, use em `github`).
   Prefira `github`; para add-ons, `imagem` também é forte.
2. **Acrescente o item** dentro de `itens` no `lista.json`, com um `id` novo e pelo menos uma
   evidência. Deixe `fonte` como `comunidade` (ou sem `fonte`); `hacs` e `home-assistant` são
   refeitos pelo importador e qualquer edição manual neles se perde.

   ```json
   {
     "id": "2026-001",
     "github": "dono/repositorio",
     "versoes": "<1.4.2",
     "nivel": "critica",
     "categoria": "comprometido",
     "motivo": "A versão 1.4.1 foi publicada por uma conta invadida e envia o token do HA para fora.",
     "evidencias": ["https://github.com/dono/repositorio/issues/123"],
     "fonte": "comunidade"
   }
   ```

3. **Assine.** O script valida a lista com as mesmas regras do CI e não assina se houver erro;
   ele também atualiza `atualizado_em`.

   ```bash
   .venv/bin/python scripts/assinar.py
   ```

4. **Faça o commit dos dois arquivos juntos e envie.** Sem o `lista.json.sig` novo, o CI falha
   na `main` e os add-ons recusam a lista (continuam com a versão anterior).

   ```bash
   git add lista.json lista.json.sig && git commit -m "Adiciona 2026-001" && git push
   ```

5. **Confira o CI** na aba *Actions* ("Validar lista" verde). Cada add-on pega a lista nova na
   primeira varredura depois que se passarem 6 horas da última busca (reiniciar o add-on não
   adianta, porque o horário da última busca fica salvo).

Para **corrigir** um item, edite-o (por exemplo, restrinja `versoes` quando sair a correção) e
repita os passos 3 e 4. Para **remover**, apague o item e repita os passos 3 e 4.

Para aceitar um **Pull Request** de outra pessoa: faça o merge, atualize sua cópia (`git pull`)
e rode os passos 3 e 4 (quem contribui não tem a chave, então o PR chega sem assinatura nova).

## Formato (`versao: 1`)

```json
{
  "versao": 1,
  "atualizado_em": "2026-11-13",
  "itens": [
    {
      "id": "2026-001",
      "tipo": "integracao",
      "github": "dono/repositorio",
      "nome": "dominio_da_integracao",
      "versoes": "<1.4.2",
      "nivel": "critica",
      "categoria": "comprometido",
      "motivo": "A versão 1.4.1 foi publicada por uma conta invadida e envia o token do HA para fora.",
      "evidencias": ["https://github.com/dono/repositorio/issues/123"],
      "adicionado_em": "2026-11-13"
    }
  ]
}
```

| Campo | Obrigatório | Descrição |
|---|---|---|
| `id` | sim | Identificador único, ex.: `2026-001`. |
| `tipo` | não | `integracao`, `frontend` (cards em `www/`) ou `addon`. Vazio = qualquer tipo. |
| `github` | um dos três | `dono/repositorio`. É a correspondência mais confiável. |
| `nome` | um dos três | Domínio da integração, pasta do card ou slug do add-on. Aceita `*` e `?`, mas não só curinga. |
| `imagem` | um dos três | Imagem do add-on, ex.: `ghcr.io/dono/{arch}-addon-x` (`{arch}` vale qualquer arquitetura). |
| `versoes` | não | Faixa afetada no formato do pip, ex.: `<1.4.2` ou `>=1.0,<1.2`. Vazio = todas. |
| `nivel` | sim | `critica`, `alta`, `media` ou `aviso`. |
| `categoria` | sim | `malicioso`, `comprometido`, `vulneravel`, `abandonado`, `telemetria`, `removido` (removido/bloqueado numa loja oficial) ou `incompativel` (versão que o próprio HA bloqueia). |
| `fonte` | não | `comunidade` (padrão para relatos), `hacs` ou `home-assistant` (itens importados; não edite à mão). |
| `motivo` | sim | Uma ou duas frases objetivas (até 500 caracteres). |
| `evidencias` | sim | De 1 a 10 links `https://` (issue, análise, CVE, aviso do autor). Na lista pessoal é opcional. |
| `adicionado_em` | não | Data `AAAA-MM-DD`. |

O formato completo está em [`schema/lista.schema.json`](schema/lista.schema.json).

## Fontes importadas

Além dos relatos da comunidade, a lista inclui o que o HACS e o Home Assistant já publicam:

| Fonte | O que entra | Nível |
|---|---|---|
| [HACS — `removed`](https://github.com/hacs/default/blob/master/removed) | Repositórios removidos da lista padrão do HACS | `critica` (crítico), `media` (blacklist), `aviso` (removido/abandonado) |
| [Home Assistant — `BLOCKED_CUSTOM_INTEGRATIONS`](https://github.com/home-assistant/core/blob/master/homeassistant/loader.py) | Versões de integrações customizadas que o HA se recusa a carregar | `alta` (ou `aviso` quando foi substituída por uma nativa) |

Os itens importados têm `fonte` `hacs` ou `home-assistant` e são refeitos a cada importação
(`scripts/importar.py`); os motivos ficam no idioma original da fonte. Toda segunda o workflow
`fontes.yml` confere se elas mudaram e falha (com aviso por e-mail) quando há algo a importar.
Os dados pertencem aos respectivos projetos: HACS (licença MIT) e Home Assistant (Apache 2.0).

Para atualizar:

```bash
.venv/bin/python scripts/importar.py
```
```bash
.venv/bin/python scripts/assinar.py
```

## Assinatura

O auditor só usa a lista se `lista.json.sig` for uma assinatura **Ed25519** válida de
`lista.json`, feita com a chave do mantenedor. A chave pública fica embutida no add-on, então
quem conseguir alterar este repositório não consegue publicar itens sem a chave privada. O
auditor também recusa uma lista com `atualizado_em` mais antigo que a que já tem.

Para publicar uma alteração, o mantenedor roda, na raiz do repositório:

```bash
.venv/bin/python scripts/assinar.py
```

O script valida a lista com as mesmas regras do CI (e não assina se houver problema), atualiza
`atualizado_em` e grava `lista.json.sig`.
`lista.json` e `lista.json.sig` precisam ir **no mesmo commit**. O `.gitattributes` impede que
o git altere as quebras de linha, porque a assinatura vale para os bytes exatos do arquivo.

## Validação automática

Todo PR passa pelo GitHub Actions (`.github/workflows/validar.yml`), que roda
`scripts/validar.py`: schema (`schema/lista.schema.json`), ids únicos, faixa de `versoes`
válida, links só `https://` e `nome` que não seja só curinga, as mesmas regras do add-on. Na
`main` ele também exige que `lista.json.sig` confira com uma chave de `chaves.json`, para pegar
alterações que foram ao ar sem assinar.

Para validar localmente:

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-ci.txt
```
```bash
.venv/bin/python scripts/validar.py
```

## Como contribuir

1. Abra um Pull Request alterando só o `lista.json`, com **um item por PR** (o mantenedor
   assina depois de aprovar).
2. Inclua pelo menos uma evidência pública e verificável. Relatos sem evidência não entram.
3. Prefira `github` a `nome`, e restrinja `versoes` quando o problema já foi corrigido.
4. Descreva fatos ("envia o token para X"), não acusações.

Itens corrigidos podem ser atualizados com a faixa de `versoes` em vez de removidos.

## Lista pessoal

Quem usa o auditor também pode manter uma lista própria, somada a esta, que vale só na própria
instalação e não precisa de assinatura nem de evidência. Ela é feita pela tela do add-on
(versão 0.12.0 ou mais nova):

1. Aba **Lista negra → Adicionar item…**, ou **Adicionar à lista negra…** na tela de um
   componente (já vem preenchido com o tipo, o GitHub e o nome).
2. Escolha o nível e a categoria, escreva o motivo e salve.
3. Clique em **Varrer agora**: o componente ganha o selo **Lista negra**.

Os itens ficam no banco do add-on e podem ser editados e removidos pela mesma aba. Não é preciso
criar pasta nem arquivo no `/config` (o arquivo `lista_negra.json` das versões anteriores não é
mais lido).

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
  "possível correspondência", um nível de severidade abaixo.

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
| `categoria` | sim | `malicioso`, `comprometido`, `vulneravel`, `abandonado` ou `telemetria`. |
| `motivo` | sim | Uma ou duas frases objetivas (até 500 caracteres). |
| `evidencias` | recomendado | Até 10 links `https://` (issue, análise, CVE, aviso do autor). |
| `adicionado_em` | não | Data `AAAA-MM-DD`. |

O formato completo está em [`schema/lista.schema.json`](schema/lista.schema.json).

## Assinatura

O auditor só usa a lista se `lista.json.sig` for uma assinatura **Ed25519** válida de
`lista.json`, feita com a chave do mantenedor. A chave pública fica embutida no add-on, então
quem conseguir alterar este repositório não consegue publicar itens sem a chave privada. O
auditor também recusa uma lista com `atualizado_em` mais antigo que a que já tem.

Para publicar uma alteração, o mantenedor roda, na raiz do repositório:

```bash
python3 scripts/assinar.py
```

O script atualiza `atualizado_em`, confere o básico do formato e grava `lista.json.sig`.
`lista.json` e `lista.json.sig` precisam ir **no mesmo commit**. O `.gitattributes` impede que
o git altere as quebras de linha, porque a assinatura vale para os bytes exatos do arquivo.

## Como contribuir

1. Abra um Pull Request alterando só o `lista.json`, com **um item por PR** (o mantenedor
   assina depois de aprovar).
2. Inclua pelo menos uma evidência pública e verificável. Relatos sem evidência não entram.
3. Prefira `github` a `nome`, e restrinja `versoes` quando o problema já foi corrigido.
4. Descreva fatos ("envia o token para X"), não acusações.

Itens corrigidos podem ser atualizados com a faixa de `versoes` em vez de removidos.

## Lista pessoal

Quem usa o auditor também pode manter uma lista própria em
`/config/security_auditor/lista_negra.json`, no mesmo formato. Ela é somada a esta.

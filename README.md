# DevSecOps Scanner

**Análise de segurança para pipelines CI/CD: SAST, SCA e deteção de segredos**

Projeto de Cibersegurança (nível Sénior/Lead) que implementa, em Python, um *scanner* de segurança
pensado para correr em *pipelines* CI/CD: **analisa o código** (SAST), **verifica as dependências**
(SCA) e **deteta credenciais expostas** (*secret detection*), produz relatórios em texto, JSON e
**SARIF 2.1.0** (o formato que o GitHub *code scanning* ingere) e **falha o *build*** quando
encontra algo acima de um limiar de severidade. Arquitetura modular, código tipado, 3 dependências
de execução e uma suíte de testes automatizados.

---

## Índice

1. [Resumo](#1-resumo)
2. [Arquitetura](#2-arquitetura)
3. [Padrões de projeto e princípios SOLID](#3-padrões-de-projeto-e-princípios-solid)
4. [Motores e regras](#4-motores-e-regras)
5. [Utilização (CLI)](#5-utilização-cli)
6. [Integração com CI/CD](#6-integração-com-cicd)
7. [Instalação e execução local](#7-instalação-e-execução-local)
8. [Testes e qualidade](#8-testes-e-qualidade)
9. [Segurança do próprio scanner (modelo de ameaças)](#9-segurança-do-próprio-scanner-modelo-de-ameaças)
10. [Limitações conhecidas e evolução](#10-limitações-conhecidas-e-evolução)
11. [Estrutura do projeto](#11-estrutura-do-projeto)
12. [Referências](#12-referências)

---

## 1. Resumo

Um *pipeline* moderno entrega código várias vezes por dia. Se a segurança só entra no fim, os
problemas chegam a produção. O DevSecOps "desloca para a esquerda" (*shift left*): cada *commit* é
verificado automaticamente, e o *build* falha cedo, quando corrigir é barato.

| Motor                | O que procura                                                                       | Onde                          |
| -------------------- | ----------------------------------------------------------------------------------- | ----------------------------- |
| **SAST**             | Padrões inseguros em código Python (injeção, desserialização, cripto fraca, TLS...) | `sast/`                       |
| **SCA**              | Dependências com vulnerabilidades conhecidas (PyPI e npm)                           | `sca/`                        |
| **Secret Detection** | Chaves, *tokens* e palavras-passe escritos no código ou em ficheiros de configuração | `secret_detection/`           |
| **Relatórios**       | Texto para humanos, JSON para *scripts*, SARIF para o GitHub                        | `reporting/`                  |

Princípio orientador: **uma ferramenta de segurança não pode ser ela própria um risco**. O scanner
nunca executa o código que analisa, nunca segue *symlinks*, nunca escreve um segredo em claro num
relatório e **nunca deixa uma análise falhada passar por limpa** (um analisador que falha faz o
*build* terminar com erro, não com sucesso).

---

## 2. Arquitetura

### 2.1 Camadas e responsabilidades

| Módulo                       | Responsabilidade (SRP)                                                            | Depende de            |
| ---------------------------- | --------------------------------------------------------------------------------- | --------------------- |
| `core/models.py`             | Contratos de dados: `Finding`, `Location`, `ScanResult`... (Pydantic v2, imutáveis) | —                     |
| `core/config.py`             | `.dsscan.toml` + validação (precedência: defeitos < ficheiro < linha de comandos) | `models`              |
| `core/filesystem.py`         | Descoberta segura de ficheiros (sem *symlinks*, com limite de tamanho)            | `config`, `models`    |
| `core/suppression.py`        | Supressões em linha (`# dsscan: ignore[REGRA]`)                                   | `filesystem`, `models`|
| `core/analyzer.py`           | Contrato `Analyzer` (a abstração que o motor conhece)                             | `filesystem`, `models`|
| `core/engine.py`             | Orquestra: percorre os ficheiros uma vez e despacha para os analisadores          | `core/*`              |
| `sast/`                      | Resolução de *imports* + regras sobre a AST                                       | `core`                |
| `sca/`                       | *Parsers* de manifestos, base de avisos, intervalos de versões                    | `core`                |
| `secret_detection/`          | Padrões, entropia, filtros de falsos positivos, redação                           | `core`                |
| `reporting/`                 | `text`, `json`, `sarif` (um `Reporter` por formato)                               | `models`              |
| `bootstrap.py`               | **Raiz de composição**: o único sítio que conhece todos os analisadores concretos | tudo                  |
| `cli.py`                     | Argumentos, códigos de saída, escrita do relatório                                | `bootstrap`, `reporting` |

As dependências apontam sempre **para dentro**: o motor não sabe o que é SARIF, os analisadores não
sabem que existe uma CLI, e os *reporters* só conhecem `ScanResult`.

### 2.2 Fluxo de um *scan*

```
dsscan scan <caminho> --format sarif --fail-on high
        |
        v
+---------------------------------------------------------------------------+
| 1. CONFIGURAÇÃO                                       core/config.py      |
|    defeitos -> .dsscan.toml -> flags   (validado com Pydantic, falha cedo)|
+---------------------------------------------------------------------------+
        |
        v
+---------------------------------------------------------------------------+
| 2. DESCOBERTA                                         core/filesystem.py  |
|    os.walk sem seguir links | ignora .git, node_modules, .venv, ...       |
|    limite de tamanho | binários ignorados | caminhos relativos POSIX      |
+---------------------------------------------------------------------------+
        |   um SourceFile de cada vez (uma só passagem pelo disco)
        v
+---------------------------------------------------------------------------+
| 3. DESPACHO                                           core/engine.py      |
|    para cada analisador que "aceita" o ficheiro:                          |
|                                                                           |
|    SastAnalyzer   (*.py)            -> ast.parse -> regras de chamadas    |
|    ScaAnalyzer    (requirements*.txt, package-lock.json) -> versões fixas |
|    SecretAnalyzer (qualquer texto)  -> padrões + entropia + filtros       |
|                                                                           |
|    falha esperada (ex.: erro de sintaxe) -> aviso, continua               |
|    falha inesperada (bug)               -> ERRO no relatório (exit 2)     |
+---------------------------------------------------------------------------+
        |   Finding | ScanIssue
        v
+---------------------------------------------------------------------------+
| 4. PÓS-PROCESSAMENTO                                  core/engine.py      |
|    supressões em linha (contadas) | deduplicação por fingerprint          |
|    ordenação determinística: severidade, ficheiro, linha, regra           |
+---------------------------------------------------------------------------+
        |   ScanResult
        v
+---------------------------------------------------------------------------+
| 5. RELATÓRIO + CÓDIGO DE SAÍDA                        reporting/, cli.py  |
|    text | json | sarif        0 = limpo | 1 = achados >= limiar | 2 = erro|
+---------------------------------------------------------------------------+
```

### 2.3 Decisões de desenho relevantes

- **O código analisado nunca é executado.** O SAST só faz `ast.parse`; nunca `import`/`exec`. Há um
  teste que o prova (código com `raise SystemExit` não interrompe o *scan*).
- **Falhar de forma segura (*fail closed*).** Se um analisador rebenta, o `ScanResult` leva um erro e
  o *exit code* é `2`, mesmo sem achados. Um *scan* partido nunca parece um *scan* limpo.
- **Segredos nunca saem em claro.** Mensagens, excertos e erros mostram apenas a forma redigida
  (`AKIA************`, sem revelar o comprimento). O `match_key` é a coluna, nunca um *hash* do
  segredo (um *hash* de um segredo fraco seria reversível por dicionário).
- **Resolução de *imports* no SAST.** `import subprocess as sp; sp.run(...)` e
  `from subprocess import run` são detetados; uma regra baseada só em texto seria contornada.
- **O SCA só avalia versões exatas.** `requests>=2.0` não diz que versão está instalada: reportar
  seria alarme falso ou falsa segurança. Essas entradas são contadas e surgem como **aviso de
  cobertura**.
- **Intervalos de versões à OSV** (`introduced <= versão < fixed`), com comparação PEP 440 via
  `packaging` (nunca comparação de *strings*).
- **Saída determinística.** Mesma entrada, mesmo relatório (ordenação estável e *fingerprints*
  estáveis), o que permite *baselines* e comparação entre execuções.
- **Caminhos relativos e POSIX** em todo o lado: o relatório é idêntico em Windows e Linux e nunca
  revela o caminho absoluto do *runner*.
- **Dependências mínimas.** Em execução: `pydantic` e `packaging`. Uma ferramenta que corre dentro
  de *pipelines* deve ter uma superfície de cadeia de fornecimento pequena.

---

## 3. Padrões de projeto e princípios SOLID

| Padrão / Princípio               | Onde                                                  | Como                                                                                                                          |
| -------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **Strategy**                     | `Analyzer`, `CallRule`, `Reporter`                    | O motor só conhece a abstração `Analyzer`; SAST, SCA e segredos são estratégias intermutáveis. Cada regra SAST é uma estratégia. |
| **Factory**                      | `get_reporter`, `build_analyzers`                     | Criam o objeto certo a partir de um nome ou da configuração.                                                                  |
| **Composition Root + DI**        | `bootstrap.py`                                        | O único módulo que importa todos os analisadores concretos; tudo o resto recebe dependências.                                 |
| **Ports & Adapters**             | `AdvisoryDatabase` + `load_advisories`, `ManifestParser` | A base de avisos e os formatos de manifesto estão atrás de interfaces pequenas: trocar a fonte não toca no analisador.     |
| **Value Object**                 | Modelos Pydantic `frozen=True`                        | Imutáveis, comparáveis por valor, `extra="forbid"` (um campo desconhecido falha em vez de ser ignorado).                      |
| **S**ingle Responsibility        | Um módulo, uma razão para mudar                       | Descobrir ficheiros, decidir o que é um achado e formatá-lo são módulos diferentes.                                           |
| **O**pen/Closed                  | Nova regra SAST, novo *parser*, novo *reporter*       | Acrescenta-se uma classe e regista-se; o analisador/motor não mudam.                                                          |
| **L**iskov                       | `Analyzer`, `Reporter`                                | Qualquer implementação é substituível; há testes com analisadores *fake* e *crashing*.                                        |
| **I**nterface Segregation        | `Reporter` (1 método), `ManifestParser` (2 métodos)   | Interfaces pequenas e focadas.                                                                                                |
| **D**ependency Inversion         | `ScanEngine` depende de `Analyzer`, não de SAST/SCA   | O núcleo não importa nenhum motor concreto.                                                                                   |

> **Nota honesta sobre o Open/Closed:** acrescentar um *ecossistema* novo ao SCA (ex.: Maven) exige
> um membro novo no `StrEnum` `Ecosystem` (além do *parser*). O mesmo vale para novos tipos de
> severidade ou de achado.

---

## 4. Motores e regras

`dsscan rules` lista todas as regras com severidade e motor.

### 4.1 SAST (código Python)

| Regra      | Severidade | CWE     | Deteta                                                                                               |
| ---------- | ---------- | ------- | ---------------------------------------------------------------------------------------------------- |
| `SAST-001` | high       | CWE-95  | `eval()` / `exec()` com argumento não constante                                                      |
| `SAST-002` | high       | CWE-78  | `os.system`, `os.popen`, `subprocess.*(..., shell=True)` com comando não constante                   |
| `SAST-003` | high       | CWE-502 | `pickle`/`marshal`/`shelve`/`dill`, `yaml.load` sem `SafeLoader`, `yaml.unsafe_load`                 |
| `SAST-004` | medium     | CWE-327 | `hashlib.md5` / `sha1` (a menos que `usedforsecurity=False`)                                         |
| `SAST-005` | high       | CWE-295 | `verify=False`, `ssl._create_unverified_context()`                                                   |
| `SAST-006` | high       | CWE-89  | `.execute()` com SQL construído por f-string, `%`, `+` ou `.format()`                                |
| `SAST-007` | medium     | CWE-377 | `tempfile.mktemp()` (condição de corrida)                                                            |
| `SAST-008` | medium     | CWE-489 | `app.run(debug=True)`                                                                                |

Uma regra é uma classe pequena:

```python
class InsecureTempfileRule(CallRule):
    rule_id = "SAST-007"
    title = "Insecure temporary file"
    severity = Severity.MEDIUM
    cwe = "CWE-377"
    remediation = "Use tempfile.mkstemp(), NamedTemporaryFile() or TemporaryDirectory()."

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        if qualified_name == "tempfile.mktemp":
            return "tempfile.mktemp() returns a name without creating the file."
        return None
```

### 4.2 SCA (dependências)

| Ficheiro                        | Ecossistema | O que é verificado                                                     |
| ------------------------------- | ----------- | ---------------------------------------------------------------------- |
| `requirements*.txt`             | PyPI        | Versões fixas (`==`, `===`); suporta marcadores, `--hash` e continuações |
| `package-lock.json` (v1, v2, v3)| npm         | Todas as versões instaladas, incluindo transitivas                     |

Cada aviso tem intervalos de versões afetadas, severidade, CVSS e referências. A **base incluída é
uma pequena amostra curada, para demonstração e testes** (4 avisos verificados em fontes públicas:
`requests`, `PyYAML`, `urllib3`, `lodash`). Para uma avaliação real, aponta `--advisories` para uma
base própria no mesmo formato (esquema validado, `schema_version: 1`) ou liga uma fonte viva (ver
secção 10).

### 4.3 Deteção de segredos

| Regra                              | Severidade | Deteta                                                       |
| ---------------------------------- | ---------- | ------------------------------------------------------------ |
| `SECRET-AWS-ACCESS-KEY-ID`         | high       | ID de chave AWS (`AKIA...`, `ASIA...`)                       |
| `SECRET-AWS-SECRET-ACCESS-KEY`     | critical   | Chave secreta AWS (40 caracteres após `aws_secret_access_key`) |
| `SECRET-GITHUB-TOKEN`              | high       | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`        |
| `SECRET-SLACK-TOKEN`               | high       | `xoxb-`, `xoxp-`, ...                                        |
| `SECRET-GOOGLE-API-KEY`            | high       | `AIza...`                                                    |
| `SECRET-STRIPE-LIVE-KEY`           | high       | `sk_live_...`, `rk_live_...`                                 |
| `SECRET-PRIVATE-KEY`               | critical   | Cabeçalho `-----BEGIN ... PRIVATE KEY-----`                  |
| `SECRET-JWT`                       | medium     | JSON Web Token                                               |
| `SECRET-CONNECTION-STRING`         | high       | Palavra-passe embebida num URL de ligação (`scheme://user:pass@host`) |
| `SECRET-GENERIC-CREDENTIAL`        | medium     | `password`/`secret`/`token`/`api_key` = valor literal com entropia suficiente |
| `SECRET-ENV-ASSIGNMENT`            | medium     | `API_KEY=valor` em ficheiros do tipo `.env`                  |

Para reduzir falsos positivos, os padrões **genéricos** passam por filtros: entropia de Shannon
mínima, *placeholders* (`changeme`, `${VAR}`, `<token>`, `your_...`), URLs, caminhos e
identificadores (`get_user_token`), e as credenciais de exemplo da documentação da AWS. Os padrões
**específicos de fornecedor** vêm primeiro e têm prioridade: um *token* do GitHub é reportado uma
vez, como *token* do GitHub, e não outra vez como credencial genérica.

### 4.4 Supressões

```python
value = eval(expression)  # dsscan: ignore[SAST-001]

# dsscan: ignore
os.system(command)
```

`ignore` sem parênteses retos silencia todas as regras; `ignore[A, B]` só essas; `ignore[]`
(vazio) **não** silencia nada. O comentário vale na mesma linha ou na linha acima (se esta só tiver o
comentário). As supressões são **contadas e mostradas** no relatório, para continuarem auditáveis.

---

## 5. Utilização (CLI)

```
dsscan scan [caminho] [opções]
dsscan rules
```

| Opção                    | Descrição                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `-f`, `--format`         | `text` (defeito), `json` ou `sarif`                                                  |
| `-o`, `--output`         | Escreve o relatório num ficheiro em vez do ecrã                                      |
| `--fail-on`              | Severidade mínima que faz o *exit code* ser 1: `none`, `info`, `low`, `medium`, `high` (defeito), `critical` |
| `--only`                 | Corre só este motor (`sast`, `sca`, `secrets`); repetível                            |
| `--exclude PADRÃO`       | *Glob* a ignorar; repetível (soma-se ao do ficheiro de configuração)                 |
| `--advisories FICHEIRO`  | Base de avisos (JSON) para o SCA                                                     |
| `--config FICHEIRO`      | Caminho para um `.dsscan.toml`                                                       |

**Códigos de saída:** `0` limpo · `1` achados ao nível do limiar ou acima · `2` erro de utilização,
de configuração, ou análise incompleta (um analisador falhou). Os erros têm prioridade sobre os
achados.

**Ficheiro `.dsscan.toml`** (na raiz do projeto analisado):

```toml
exclude = ["tests", "docs/examples", "*.md"]   # sem "/" = qualquer componente do caminho
fail_on = "high"                                # "none" desativa a falha do build
max_file_size_bytes = 1000000
analyzers = ["sast", "sca", "secrets"]
advisories_path = "my-advisories.json"          # relativo ao ficheiro de configuração
```

---

## 6. Integração com CI/CD

O repositório inclui `.github/workflows/ci.yml` com dois trabalhos:

1. **`quality`**: `ruff`, `mypy` e `pytest` (Python 3.11, 3.12 e 3.13).
2. **`self-scan`** (*dogfooding*): o scanner analisa o próprio repositório e envia o SARIF para o
   separador **Security > Code scanning** do GitHub.

Para usar noutro projeto:

```yaml
permissions:
  contents: read
  security-events: write          # necessário para enviar SARIF

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with: { python-version: "3.12" }
  - run: pip install devsecops-scanner     # ou: pip install .
  - run: dsscan scan . --format sarif --output dsscan.sarif --fail-on high
  - if: always()
    uses: github/codeql-action/upload-sarif@v4
    with: { sarif_file: dsscan.sarif }
```

Boa prática: em produção, fixar as *actions* de terceiros por *commit SHA* completo.

---

## 7. Instalação e execução local

Requisitos: **Python 3.11 ou superior**.

```powershell
# Windows (PowerShell), na pasta do projeto
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1          # se for bloqueado: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install --upgrade pip
pip install -r requirements-dev.txt # só execução: pip install -r requirements.txt
```

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

Primeiros passos:

```
dsscan rules                          # lista as regras
dsscan scan .                         # analisa o diretório atual
dsscan scan src --format json         # JSON no ecrã
dsscan scan . -f sarif -o dsscan.sarif --fail-on medium
python -m devsecops_scanner scan .    # equivalente, sem o comando instalado
```

Exemplo de saída (texto):

```
[HIGH] SAST-002 app/main.py:13:5
  OS command injection risk
  os.system() runs a non-constant command through a shell.
  > os.system("ping " + user_input)
  Fix: Pass the command as a list of arguments without shell=True, ...
  Ref: CWE-78

[HIGH] SECRET-AWS-ACCESS-KEY-ID app/main.py:9:11
  AWS access key ID
  Possible AWS access key ID found in the source. The value is redacted in this report.
  > AWS_KEY = "AKIA************"
```

---

## 8. Testes e qualidade

```
pytest                                       # toda a suíte
pytest tests/test_sast.py -v                 # só o SAST
pytest --cov --cov-report=term-missing       # com cobertura (o CI exige >= 85 %)
ruff format .                                # formata
ruff check .                                 # lint (inclui regras de segurança "S" / bandit)
mypy                                         # tipagem estrita (strict, configurada em pyproject.toml)
```

| Ficheiro                    | Tipo                   | O que garante                                                                                                                       |
| --------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `tests/test_models.py`      | Unitários              | Validação estrita, imutabilidade, caminhos inseguros rejeitados, *fingerprint* estável, severidades e limiares                      |
| `tests/test_config.py`      | Unitários              | Defeitos seguros, precedência, TOML inválido, erros **sem eco** dos valores                                                         |
| `tests/test_filesystem.py`  | Unitários              | Exclusões, binários, ficheiros grandes, UTF-8/BOM, ordem determinística, ***symlinks* não seguidos**                                |
| `tests/test_suppression.py` | Unitários              | Estilos de comentário, `ignore[]` vazio, linha acima, regra específica                                                              |
| `tests/test_engine.py`      | Unitários + integração | Despacho, deduplicação, ordenação, isolamento de falhas (**um crash não esconde os outros motores nem a mensagem do erro**)         |
| `tests/test_sast.py`        | Unitários              | Cada regra (positivos e negativos), resolução de *aliases*, erros de sintaxe, código aninhado ao extremo, o código **não é executado** |
| `tests/test_sca.py`         | Unitários + integração | Intervalos de versões (limites), PEP 503, *parsers* (marcadores, hashes, continuações, lockfile v1/v3), base de avisos, avisos de cobertura |
| `tests/test_secrets.py`     | Unitários              | Cada padrão, *placeholders*, entropia, redação, **o segredo nunca aparece em nenhum campo**, linha hostil de 200 000 caracteres sem bloquear |
| `tests/test_reporting.py`   | Unitários              | Texto, JSON, SARIF (níveis, `ruleIndex`, CWE, URIs codificados, notificações), **sanitização de sequências de escape**              |
| `tests/test_cli.py`         | Integração             | Códigos de saída, `--fail-on`, `--only`, `--exclude`, configuração vs. *flags*, escrita de ficheiro, erros                          |
| `tests/test_integration.py` | Ponta a ponta          | Projeto realista (os 3 motores), execução como subprocesso, determinismo, ***dogfooding*** (o scanner analisa-se a si próprio)     |

As credenciais de teste são **construídas em tempo de execução** (`tests/helpers.py`) e nunca
escritas como literais: o repositório fica limpo para o próprio scanner e para o *push protection*
do GitHub. Os testes correm sem rede nem serviços externos.

---

## 9. Segurança do próprio scanner (modelo de ameaças)

Um scanner lê código **não confiável** (de *pull requests*, por exemplo). Tem de assumir que a
entrada é hostil.

| Ameaça                                                                           | Mitigação                                                                                                                      |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Repositório com *symlink* para fora da raiz (ler `/etc/passwd`, chaves SSH)      | Não segue ficheiros nem diretórios *symlink* (um aviso por cada ficheiro ignorado)                                              |
| Execução de código do projeto analisado                                          | Só `ast.parse`; nunca `import`, `exec`, `eval` nem *plugins* do alvo                                                            |
| Ficheiros gigantes / exaustão de memória                                         | Limite de tamanho por ficheiro (1 MB por defeito), configuração e base de avisos com limite                                    |
| ReDoS (regex catastrófica numa linha hostil)                                     | Todos os quantificadores são limitados; teste com linhas de 200 000 caracteres                                                  |
| Injeção de sequências ANSI / falsas linhas de log via código analisado           | O relatório de texto substitui caracteres de controlo; JSON em ASCII; SARIF é JSON                                              |
| Fuga de segredos para o relatório ou para os logs do CI                          | Valores redigidos; `match_key` é a coluna (não um *hash*); erros e logs mostram só o **tipo** da exceção                        |
| Configuração ou base de avisos maliciosa                                         | Esquema estrito (`extra="forbid"`), limite de tamanho, erros que indicam o campo mas **nunca repetem o valor**                  |
| Analisador a falhar em silêncio e o *build* passar "verde"                       | Falha inesperada = erro no relatório e *exit code* 2                                                                            |
| Caminhos absolutos / `..` nos relatórios                                         | `Location` valida caminho relativo POSIX sem `..`                                                                               |
| Cadeia de fornecimento do próprio scanner                                        | 2 dependências de execução; CI com permissões mínimas; `ruff` com regras `bandit` (`S`)                                         |

---

## 10. Limitações conhecidas e evolução

Este é um projeto académico com arquitetura orientada a produção. O que **falta**, e onde se encaixa:

| Limitação atual                                                                                 | Evolução                                                                                                |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **SAST só para Python** e baseado em padrões de chamadas: não há análise de fluxo de dados (*taint*), por isso `eval(x)` é sempre sinalizado mesmo que `x` venha de uma constante noutro sítio | Análise de *taint* intra-procedimento; novos `Analyzer` para JavaScript/Go                                |
| Os *aliases* por atribuição não são seguidos (`p = pickle; p.loads(x)`)                         | Resolução de atribuições simples na `ImportMap`                                                         |
| **Base de avisos de amostra** (4 entradas)                                                      | Novo *loader* para o OSV / GitHub Advisory Database (a interface `AdvisoryDatabase` já o permite)       |
| SCA só avalia versões **exatas**; `requirements.txt` não resolve dependências transitivas       | Resolver a árvore (`pip-compile`/`uv lock`); suporte a `poetry.lock`, `yarn.lock`, `pnpm-lock.yaml`     |
| Segredos: heurísticas (regex + entropia) com falsos positivos e negativos; não analisa o **histórico do Git** | Modo `--git-history`; validação ativa de credenciais (com consentimento explícito); *baseline* de achados |
| As supressões são textuais: um literal de texto com `dsscan: ignore` na mesma linha também suprime | Ler só comentários reais (módulo `tokenize` em Python)                                                  |
| O `fingerprint` existe, mas ainda não há *baseline* (`--baseline`) nem *diff* entre execuções   | Ficheiro de *baseline* para só falhar em achados **novos**                                              |
| Sem paralelismo: um ficheiro de cada vez                                                        | `ProcessPoolExecutor` por ficheiro (os analisadores são puros)                                          |
| Sem análise de IaC (Dockerfile, Terraform, Kubernetes)                                          | Novos analisadores por tipo de ficheiro                                                                 |

---

## 11. Estrutura do projeto

```
devsecops-scanner/
├── src/devsecops_scanner/
│   ├── __init__.py
│   ├── __main__.py              # python -m devsecops_scanner
│   ├── cli.py                   # argumentos, códigos de saída
│   ├── bootstrap.py             # raiz de composição (DI)
│   ├── py.typed                 # marca o pacote como tipado (PEP 561)
│   ├── core/
│   │   ├── models.py            # Finding, Location, ScanResult... (Pydantic v2)
│   │   ├── config.py            # .dsscan.toml + validação
│   │   ├── errors.py            # hierarquia de exceções
│   │   ├── filesystem.py        # descoberta segura de ficheiros
│   │   ├── suppression.py       # # dsscan: ignore[...]
│   │   ├── analyzer.py          # contrato Analyzer (Strategy)
│   │   └── engine.py            # orquestração
│   ├── sast/
│   │   ├── analyzer.py          # SastAnalyzer
│   │   ├── imports.py           # resolução de nomes qualificados
│   │   └── rules/               # base.py, injection.py, crypto_and_config.py
│   ├── sca/
│   │   ├── analyzer.py          # ScaAnalyzer
│   │   ├── models.py            # Advisory, VersionRange, Dependency
│   │   ├── parsers.py           # requirements.txt, package-lock.json
│   │   ├── advisories.py        # carregamento + índice da base de avisos
│   │   └── data/advisories.json # amostra curada
│   ├── secret_detection/
│   │   ├── analyzer.py          # SecretAnalyzer
│   │   ├── patterns.py          # padrões por fornecedor + genéricos
│   │   └── heuristics.py        # entropia, placeholders, redação
│   └── reporting/               # text, json_reporter, sarif
├── tests/                       # helpers.py, conftest.py e test_*.py
├── .github/workflows/ci.yml     # qualidade + self-scan com upload de SARIF
├── .dsscan.toml                 # configuração do self-scan
├── pyproject.toml               # build, pytest, coverage, mypy, ruff
├── requirements.txt             # execução
├── requirements-dev.txt         # + testes e análise estática
├── .gitignore
└── README.md
```

---

## 12. Referências

- OWASP, *Top 10:2021* (A02 Cryptographic Failures, A03 Injection, A06 Vulnerable and Outdated Components).
- MITRE, *CWE* (CWE-78, 89, 95, 295, 327, 377, 489, 502, 798). <https://cwe.mitre.org/>
- OASIS, *Static Analysis Results Interchange Format (SARIF) Version 2.1.0*.
- OpenSSF, *OSV Schema* (intervalos `introduced`/`fixed`). <https://ossf.github.io/osv-schema/>
- NIST, *SP 800-218, Secure Software Development Framework (SSDF)*.
- Python Packaging Authority, *PEP 440* (versões) e *PEP 503* (normalização de nomes).
- Gamma, Helm, Johnson, Vlissides, *Design Patterns: Elements of Reusable Object-Oriented Software*.
- Martin, R. C., *Agile Software Development: Principles, Patterns, and Practices* (SOLID).

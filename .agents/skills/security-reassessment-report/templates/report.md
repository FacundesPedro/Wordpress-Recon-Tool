# Relatório de Reavaliação de Segurança
## SOC – Data Center

Alvo: **{{target}}**
Data da reavaliação: **{{data_reavaliacao}}**
Avaliação de referência: **{{data_avaliacao_anterior}}**

### Aviso de Confidencialidade

Este relatório contém informações sensíveis, privilegiadas e confidenciais. Precauções devem ser tomadas para proteger a confidencialidade deste documento. A publicação deste relatório pode causar danos à reputação da organização e facilitar ataques contra os objetos da análise e a infraestrutura relacionada.

### Isenção de responsabilidade

Esta avaliação pode não revelar todos os problemas de segurança que afetam os objetos analisados. Este relatório é um resumo das descobertas da avaliação realizada. Quaisquer alterações no ambiente durante o período dos testes podem afetar os resultados da avaliação. **Nenhuma exploração destrutiva foi executada**; {{frase_nao_destrutiva}}.

---

## Índice

- Sumário Executivo
- Escopo
  - Serviços
  - Sites
- Metodologia da Reavaliação
- Classificação de Definições
  - Classificação de Riscos
  - Classificação de Probabilidade de Exploração
  - Classificação de Impacto ao Negócio
  - Classificação de Dificuldade de Remediação
  - Classificação do Tratamento Aplicado
- Achados da Avaliação – Serviços
- Achados da Avaliação – {{site_1}}
- Achados da Avaliação – {{site_2}}
- Observação
- Recomendações Gerais
- Apêndice A – Ferramentas Usadas
- Apêndice B – Siglas

---

## Sumário Executivo

A reavaliação de segurança realizada nos sites {{sites}} e nos servidores da infraestrutura onde ambos estão hospedados ocorreu entre os dias {{data_inicio}} e {{data_fim}}. O propósito da nova avaliação foi verificar se as recomendações de segurança foram aplicadas e efetuar testes não feitos na avaliação anterior. Nessa nova avaliação foram identificadas a persistência de {{n_persistentes}} vulnerabilidades de nível {{nivel_persistente}}, {{n_novas}} novas vulnerabilidades de nível {{nivel_novo}} e a mitigação de {{n_mitigadas}} vulnerabilidades de nível {{nivel_mitigado}}.

| Período | Crítica | Alta | Média | Baixa |
|---------|---------|------|-------|-------|
| **Antes** | {{antes_critica}} | {{antes_alta}} | {{antes_media}} | {{antes_baixa}} |
| **Depois** | {{depois_critica}} | {{depois_alta}} | {{depois_media}} | {{depois_baixa}} |

**Principais riscos:**

- {{risco_1}};
- {{risco_2}};
- {{risco_3}}.

**O que fazer agora (em ordem de prioridade):**

1. {{acao_1}};
2. {{acao_2}};
3. {{acao_3}}.

---

## Escopo

{{escopo_texto}}

### Serviços

| Nome do host | Endereço IP |
|--------------|-------------|
| {{host_1}} | {{ip_1}} |

### Sites

| Endereço | Endereço IP |
|----------|-------------|
| {{url_1}} | {{ip_url_1}} |

---

## Metodologia da Reavaliação

A nova avaliação considerou, assim como na anterior, os pontos de fragilidade relacionados aos serviços expostos nos servidores. Os procedimentos dessa nova avaliação foram executados seguindo o fluxo descrito a seguir:

1. Enumerar e validar informações dos serviços expostos nos servidores e comparar com os achados anteriores;
2. Verificar novos caminhos de exploração;
3. Explorar as vulnerabilidades conhecidas que foram encontradas;
4. Documentar as informações sobre as fragilidades exploradas e outras que sejam relevantes no aspecto de segurança.

---

## Classificação de Definições

### Classificação de Riscos

| Nível | Pontuação | Descrição |
|-------|-----------|-----------|
| Crítico | 10 | A vulnerabilidade possui uma imediata ameaça para a organização. Uma exploração bem-sucedida pode afetar permanentemente a organização. A mitigação precisa ser implementada imediatamente. |
| Alto | 7-9 | A vulnerabilidade possui uma imediata ameaça para a organização. A mitigação deve ser priorizada. |
| Médio | 4-6 | A exploração bem-sucedida é possível e pode resultar em interrupção notável da funcionalidade do negócio. Essa vulnerabilidade deve ser corrigida quando possível. |
| Baixo | 1-3 | A vulnerabilidade representa uma ameaça insignificante/mínima para a organização. A presença dessa vulnerabilidade deve ser observada e corrigida, se possível. |
| Informação | 0 | Essas descobertas não representam uma ameaça clara para a organização, mas podem fazer com que os processos de negócios funcionem de maneira diferente do desejado ou revelar informações confidenciais sobre a empresa. |

### Classificação de Probabilidade de Exploração

| Probabilidade | Descrição |
|---------------|-----------|
| Provável | Os métodos de exploração são bem conhecidos e podem ser executados usando ferramentas disponíveis publicamente. Atacantes pouco qualificados e ferramentas automatizadas podem explorar com sucesso a vulnerabilidade com dificuldade mínima. |
| Possível | Os métodos de exploração são bem conhecidos, podem ser executados usando ferramentas públicas, mas requerem configuração. A compreensão do sistema subjacente é necessária para uma exploração bem-sucedida. |
| Improvável | A exploração requer uma compreensão profunda dos sistemas subjacentes ou habilidades técnicas avançadas. Condições precisas podem ser necessárias para uma exploração bem-sucedida. |

### Classificação de Impacto ao Negócio

| Impacto | Descrição |
|---------|-----------|
| Maior | A exploração bem-sucedida pode resultar em grandes interrupções de funções críticas de negócios em toda a organização e danos financeiros significativos. |
| Moderada | A exploração bem-sucedida pode causar interrupções significativas em funções de negócios não críticas. |
| Menor | A exploração bem-sucedida pode afetar poucos usuários, sem causar muita interrupção nas funções de negócios de rotina. |

### Classificação de Dificuldade de Remediação

| Dificuldade | Descrição |
|-------------|-----------|
| Difícil | A correção pode exigir uma extensa reconfiguração dos sistemas subjacentes que consome muito tempo. A correção pode exigir a interrupção das funções comerciais normais. |
| Moderada | A correção pode exigir pequenas reconfigurações ou adições que podem ser demoradas ou caras. |
| Fácil | A correção pode ser realizada em um curto espaço de tempo, com pouca dificuldade. |

### Classificação do Tratamento Aplicado

| Tratamento | Descrição |
|------------|-----------|
| Mitigado | A fragilidade foi corrigida e as novas verificações comprovaram a eficácia do controle empregado no ambiente. |
| Parcialmente mitigado | Parte das fragilidades foi corrigida; os itens pendentes permanecem exploráveis e são reportados novamente em "Achados encontrados". |
| Não mitigado | A fragilidade permanece sem correção na data da reavaliação, conforme as novas verificações realizadas. |

---

## Achados da Avaliação – {{escopo}}

### – Achados encontrados (resumo)

| Número | Achado | Pontuação de risco | Risco | Interno/Externo |
|--------|--------|--------------------|-------|-----------------|
| {{n}} | {{titulo}} | {{score}} | {{risco}} | {{interno_externo}} |

### – Achados encontrados (detalhes)

#### {{n}} – {{titulo}}

**{{Risco}} ({{score}})**

| Probabilidade de Exploração | Impacto ao Negócio | Dificuldade de Remediação |
|-----------------------------|--------------------|---------------------------|
| {{probabilidade}} | {{impacto}} | {{remediacao}} |

**Implicações de Segurança**

{{implicacoes}}

**Análise**

{{analise}} (Figuras {{n}} a {{m}}).

**Evidências**

![Figura {{n}} – {{o_que_a_figura_prova}}]({{caminho_imagem}})

```
{{comando}}
{{saida_relevante}}
```

Evidências: {{caminhos}}.

**Recomendações**

1. {{recomendacao}};
2. {{como_conferir}}.

**Referências**

- {{referencia_url}};

### – Achados tratados (resumo)

| Número | Achado | Classificação do tratamento | Interno/Externo |
|--------|--------|------------------------------|-----------------|
| {{n}} | {{titulo}} | {{classificacao}} | {{interno_externo}} |

### – Achados tratados (detalhes)

#### {{n}} – {{titulo}}

| Tratamento aplicado | {{classificacao}} |
|---------------------|-------------------|

**Controle empregado**

{{controle_empregado}}

**Análise**

{{analise_reteste}} (Figuras {{n}} a {{m}}).

**Evidências**

![Figura {{n}} – {{o_que_a_figura_prova}}]({{caminho_imagem}})

```
{{comando}}
{{saida_relevante}}
```

Evidências: {{caminhos}}.

**Recomendações**

1. {{recomendacao}};
2. {{como_conferir}}.

**Referências**

- {{referencia_url}};

---

## Observação

{{texto_observacao}}

**Evidências**

![Figura {{n}} – {{o_que_a_figura_prova}}]({{caminho_imagem}})

```
{{comando}}
{{saida_relevante}}
```

Evidências: {{caminhos}}.

---

## Recomendações Gerais

Recomenda-se, com base na reavaliação, que sejam aplicadas as seguintes ações de segurança:

1. Manter os softwares sempre atualizados com a versão mais recente e estável;
2. Corrigir os achados novos e os anteriores que estão pendentes de correção;
3. Aplicar as boas práticas recomendadas (*hardening*) para os softwares instalados;
4. {{recomendacao_especifica}};

---

## Apêndice A – Ferramentas Usadas

| Ferramenta | Descrição |
|------------|-----------|
| {{ferramenta_1}} | {{descricao_ferramenta_1}} |

**Tabela A.1:** Ferramentas usadas durante a reavaliação.

## Apêndice B – Siglas

| Sigla | Descrição de uso |
|-------|------------------|
| {{sigla_1}} | {{descricao_sigla_1}} |

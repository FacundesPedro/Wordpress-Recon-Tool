# Relatório de Avaliação de Segurança
## SOC – Data Center

Alvo: **{{target}}**
Data da avaliação: **{{data_avaliacao}}**

### Aviso de Confidencialidade

Este relatório contém informações sensíveis, privilegiadas e confidenciais. Precauções devem ser tomadas para proteger a confidencialidade deste documento. A publicação deste relatório pode causar danos à reputação da organização e facilitar ataques contra os objetos da análise e a infraestrutura relacionada.

### Isenção de responsabilidade

Esta avaliação pode não revelar todos os problemas de segurança que afetam os objetos analisados. Este relatório é um resumo das descobertas da avaliação realizada. Quaisquer alterações no ambiente durante o período dos testes podem afetar os resultados da avaliação. **Nenhuma exploração destrutiva foi executada**; {{frase_nao_destrutiva}}.

---

## Índice

- Sumário Executivo
- Escopo
- Serviços
- Endereço
- Metodologia da Avaliação
- Classificações
  - Classificação de Riscos
  - Classificação de Probabilidade de Exploração
  - Classificação de Impacto ao Negócio
  - Classificação de Dificuldade de Remediação
- Achados da Avaliação
- Recomendações Gerais
- Apêndice A – Ferramentas Usadas
- Apêndice B – Siglas
- Apêndice C – Observações e Falsos Positivos

---

## Sumário Executivo

{{sumario_contexto}}

{{sumario_resultado}}

| Crítica | Alta | Média | Baixa | Informação |
|---------|------|-------|-------|------------|
| {{n_critica}} | {{n_alta}} | {{n_media}} | {{n_baixa}} | {{n_info}} |

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

- {{escopo_item_1}}
- {{escopo_item_2}}

---

## Serviços

| Serviço | Versão/Detalhe |
|---------|----------------|
| {{servico_1}} | {{detalhe_1}} |
| {{servico_2}} | {{detalhe_2}} |

## Endereço

| Endereço IP | URL |
|-------------|-----|
| {{ip}} | {{url}} |

> {{observacao_endereco}}

---

## Metodologia da Avaliação

A avaliação realizada seguiu as etapas abaixo:

1. Enumerar os possíveis caminhos de exploração;
2. Testar os possíveis caminhos de exploração encontrados (**de forma não destrutiva**);
3. Revisar as informações coletadas;
4. Documentar as informações sobre as fragilidades exploradas e outras informações relevantes no aspecto de segurança.

---

## Classificações

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

---

## Achados da Avaliação

### – Achados encontrados (resumo)

| Número | Achado | Pontuação de risco | Risco | Interno/Externo |
|--------|--------|--------------------|-------|-----------------|
| 1 | {{achado_1}} | {{score_1}} | {{risco_1}} | {{escopo_1}} |

---

### – Achados encontrados (detalhes)

## 1 – {{titulo_achado_1}}

**{{risco_1}} ({{score_1}})**

| Probabilidade de Exploração | Impacto ao Negócio | Dificuldade de Remediação |
|-----------------------------|--------------------|---------------------------|
| {{probabilidade_1}} | {{impacto_1}} | {{remediacao_1}} |

**Implicações de Segurança**

{{implicacoes_1}}

**Análise**

{{analise_1}}

**Evidências**

![Figura {{n_figura}} – {{o_que_a_figura_prova}}]({{caminho_imagem}})

```
{{comando_1}}
{{saida_1}}
```

Evidências: {{arquivos_1}}.

**Recomendação**

1. {{passo_1}};
2. {{passo_2}};
3. {{como_conferir}}.

---

## Recomendações Gerais

Recomenda-se, com base na avaliação, que sejam adotadas as seguintes ações de segurança:

1. {{recomendacao_geral_1}};
2. {{recomendacao_geral_2}};
3. Manter os softwares sempre atualizados com a versão mais recente e estável;
4. Aplicar boas práticas de segurança (*hardening*) nos serviços analisados;
5. Revisar periodicamente os controles de segurança empregados.

---

## Apêndice A – Ferramentas Usadas

| Ferramenta | Descrição |
|------------|-----------|
| {{ferramenta_1}} | {{descricao_ferramenta_1}} |

## Apêndice B – Siglas

| Sigla | Descrição de uso |
|-------|------------------|
| {{sigla_1}} | {{descricao_sigla_1}} |

## Apêndice C – Observações e Falsos Positivos

- {{observacao_1}}

### Índice de evidências

| Arquivo | Conteúdo |
|---------|----------|
| {{arquivo_evidencia_1}} | {{conteudo_evidencia_1}} |

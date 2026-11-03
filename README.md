# 🔎 Detector de phishing pela URL

Aplicação desenvolvida no Projeto Integrador do curso de Ciência de Dados da Fatec Rubens Lara (Santos-SP).

O app recebe um endereço de site e estima a probabilidade de ser um golpe de **phishing**, analisando **apenas o texto da URL**, sem abrir a página.

## Como funciona

1. O usuário cola uma URL.
2. A função `extrair_variaveis` calcula 14 características do endereço (tamanho, caracteres especiais, uso de HTTPS, entre outras), a mesma usada no treinamento.
3. As variáveis são padronizadas e aplicadas à Regressão Logística treinada (arquivo `modelo_B_parametros.json`).
4. O app mostra a probabilidade de phishing e quais variáveis mais pesaram na decisão.

## Desempenho

- Base de treino: PhiUSIIL Phishing URL Dataset (UCI).
- Recall para phishing no conjunto de teste: **97,10%**.
- Recall em golpes brasileiros recentes (PhishTank, 2024 a 2026): **83,58%**.

## Limitação

Golpes com endereço curto, HTTPS e nome de marca no domínio (ex.: `antivirusbradesco[.]com`) tendem a ser classificados como legítimos, pois o modelo analisa o formato da URL, e não o uso indevido de marcas.

## Arquivos

- `app.py`: aplicação Streamlit
- `modelo_B_parametros.json`: modelo treinado (padronização e coeficientes)
- `requirements.txt`: bibliotecas necessárias
- `PI4_phishing_(8).ipynb`: notebook com todo o desenvolvimento

## Como executar localmente

pip install -r requirements.txt
streamlit run app.py

---
Projeto acadêmico. Não substitui ferramentas profissionais de segurança.

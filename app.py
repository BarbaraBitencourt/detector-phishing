# app de detecção de phishing pelo endereço (cenário b do projeto)
# o usuário cola uma url, o app calcula as 14 variáveis com a mesma função do treino
# e aplica a regressão logística salva no colab, sem abrir a página

import json
import math
import re
from urllib.parse import urlsplit

import pandas as pd
import streamlit as st

st.set_page_config(page_title='Detector de phishing pela URL', page_icon='🔎')

# ---------------------------------------------------------------
# 1. mesma função de extração de variáveis usada no treino (colab)
# ---------------------------------------------------------------
padrao_ip = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def maior_sequencia(texto, teste):
    # tamanho da maior sequência seguida de caracteres que passam no teste
    maior = atual = 0
    for c in texto:
        atual = atual + 1 if teste(c) else 0
        maior = max(maior, atual)
    return maior

def extrair_variaveis(url):
    url = str(url).strip()
    partes = urlsplit(url)                          # separa protocolo, domínio, caminho...
    dominio = (partes.hostname or '').lower()       # ex.: www.itau.com.br
    tld = dominio.rsplit('.', 1)[-1] if '.' in dominio else ''   # ex.: br

    tamanho = len(url)
    letras = sum(c.isascii() and c.isalpha() for c in url)
    digitos = sum(c.isdigit() for c in url)
    iguais = url.count('=')
    interrog = url.count('?')
    ecomercial = url.count('&')
    ofuscados = len(re.findall(r'%[0-9a-fA-F]{2}', url))   # tipo %20, %2F
    outros = sum((not c.isalnum()) and c not in '=?&' for c in url)

    # continuidade: maior sequência de letras + de dígitos + de símbolos, dividido pelo tamanho
    eh_letra = lambda c: c.isascii() and c.isalpha()
    eh_digito = lambda c: c.isdigit()
    eh_especial = lambda c: not c.isalnum()
    continuidade = (maior_sequencia(url, eh_letra) + maior_sequencia(url, eh_digito)
                    + maior_sequencia(url, eh_especial)) / tamanho if tamanho else 0

    return {
        'URLLength': tamanho,
        'DomainLength': len(dominio),
        'IsDomainIP': int(bool(padrao_ip.match(dominio))),
        'CharContinuationRate': continuidade,
        'TLDLength': len(tld),
        'NoOfSubDomain': max(dominio.count('.') - 1, 0),
        'HasObfuscation': int(ofuscados > 0),
        'NoOfObfuscatedChar': ofuscados,
        'LetterRatioInURL': letras / tamanho if tamanho else 0,
        'DegitRatioInURL': digitos / tamanho if tamanho else 0,
        'NoOfEqualsInURL': iguais,
        'NoOfQMarkInURL': interrog,
        'NoOfAmpersandInURL': ecomercial,
        'NoOfOtherSpecialCharsInURL': outros,
        'SpacialCharRatioInURL': outros / tamanho if tamanho else 0,
        'IsHTTPS': int(partes.scheme.lower() == 'https'),
    }

# nomes em português, os mesmos dos gráficos do artigo
NOMES_PT = {
    'URLLength': 'Tamanho da URL',
    'DomainLength': 'Tamanho do domínio',
    'IsDomainIP': 'Domínio é um IP',
    'CharContinuationRate': 'Continuidade de caracteres',
    'TLDLength': 'Tamanho da extensão (TLD)',
    'NoOfSubDomain': 'Qtd. de subdomínios',
    'IsHTTPS': 'Usa HTTPS',
    'DegitRatioInURL': 'Proporção de dígitos',
    'NoOfQMarkInURL': 'Qtd. de "?"',
    'NoOfAmpersandInURL': 'Qtd. de "&"',
    'NoOfOtherSpecialCharsInURL': 'Qtd. de caracteres especiais',
    'SpacialCharRatioInURL': 'Proporção de caracteres especiais',
    'HasObfuscation': 'Possui ofuscação',
    'NoOfObfuscatedChar': 'Qtd. de caracteres ofuscados',
}

# ---------------------------------------------------------------
# 2. carregando o modelo salvo no colab
# (médias e desvios da padronização + coeficientes da regressão logística)
# ---------------------------------------------------------------
@st.cache_resource
def carregar_modelo():
    with open('modelo_B_parametros.json', encoding='utf-8') as f:
        return json.load(f)

modelo = carregar_modelo()

def prever(url):
    valores = extrair_variaveis(url)
    linhas = []
    soma = modelo['intercepto']
    for col, media, desvio, coef in zip(modelo['colunas'], modelo['media'],
                                        modelo['desvio'], modelo['coeficientes']):
        z = (valores[col] - media) / desvio          # mesma padronização do treino
        contrib = coef * z                           # quanto essa variável empurra a decisão
        soma += contrib
        # o coeficiente é da classe 1 (legítima); invertendo o sinal fica "a favor do phishing"
        linhas.append({'Variável': NOMES_PT.get(col, col), 'Valor': round(valores[col], 3),
                       'Peso para phishing': -contrib})
    prob_legitima = 1 / (1 + math.exp(-soma))
    return 1 - prob_legitima, pd.DataFrame(linhas)

# ---------------------------------------------------------------
# 3. tela
# ---------------------------------------------------------------
st.title('🔎 Detector de phishing pela URL')
st.write('Cole um endereço de site. O modelo analisa **apenas o texto da URL**, '
         'sem abrir a página, e estima a probabilidade de ser um golpe de *phishing*.')

url = st.text_input('Endereço (URL)', placeholder='https://www.exemplo.com.br')

if st.button('Analisar', type='primary') and url.strip():
    url = url.strip()
    if not url.lower().startswith(('http://', 'https://')):
        url = 'https://' + url
        st.info(f'Endereço analisado: {url} (o https:// foi incluído automaticamente).')
    prob, tabela = prever(url)

    if prob >= 0.5:
        st.error(f'⚠️ **Provável phishing** – probabilidade de {prob:.0%}')
    else:
        st.success(f'✅ **Provavelmente legítima** – probabilidade de phishing de {prob:.0%}')
    st.progress(min(max(prob, 0.0), 1.0))

    st.subheader('Por que o modelo decidiu assim?')
    st.caption('Valores positivos aumentam a chance de phishing; negativos aumentam a chance de ser legítima.')
    tabela = tabela.reindex(tabela['Peso para phishing'].abs().sort_values(ascending=False).index)
    st.bar_chart(tabela.set_index('Variável')['Peso para phishing'].head(6))
    st.dataframe(tabela.round(3), hide_index=True, width='stretch')

with st.expander('Sobre o modelo'):
    st.write(
        '- **Modelo:** Regressão Logística com padronização, treinada na base PhiUSIIL (UCI).\n'
        '- **Variáveis:** 14 características calculadas apenas a partir do texto da URL.\n'
        '- **Desempenho no teste:** recall de 97,10% para phishing; em golpes brasileiros '
        'recentes, recall de 83,58%.\n'
        '- **Limitação:** golpes com endereço curto, HTTPS e nome de marca no domínio '
        '(ex.: antivirusbradesco[.]com) tendem a passar como legítimos.\n'
        '- Projeto acadêmico – Fatec Rubens Lara, Ciência de Dados. Não substitui ferramentas de segurança.'
    )

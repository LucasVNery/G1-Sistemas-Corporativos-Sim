# Resumo da Conversa — Sistemas de Segurança

## 1. Análise do contexto do problema
Análise dos 4 problemas identificados pela empresa:
- Documentos trafegando sem proteção na rede
- Ausência de garantia de autoria
- Arquivos no servidor sem proteção em repouso
- Equipe sem critério técnico para escolher o tipo de criptografia

Cada problema foi mapeado a um mecanismo: confidencialidade (AES), autenticidade (RSA + assinatura), integridade (Hash), troca de chaves (RSA).

---

## 2. Criptografia simétrica vs. assimétrica
Esclarecimento da diferença entre os dois tipos:
- **Simétrica**: uma única chave para cifrar e decifrar (AES)
- **Assimétrica**: par de chaves pública/privada (RSA) — essa é a de chave pública e privada

---

## 3. Por que não usar só a assimétrica?
Mesmo tratando-se de um único projeto, não seria correto usar apenas a assimétrica.
A assimétrica é lenta para grandes volumes de dados. A solução correta é o **híbrido**: RSA gerencia a confiança, AES protege o conteúdo.

---

## 4. Usar ambas as criptografias juntas
Confirmação de que o correto é usar as duas em conjunto, cada uma no papel que desempenha melhor — isso se chama **criptografia híbrida**.

---

## 5. Problema 4 — questão humana
O problema 4 não é de código, mas de **conhecimento técnico da equipe**.
A equipe identificou a necessidade de criptografia mas não soube qual aplicar em cada situação — risco de criar uma falsa sensação de segurança (Security by Obscurity).

---

## 6. Planejamento do desenvolvimento em Python
Definição do plano de implementação em 4 arquivos Python usando a biblioteca `cryptography`:

| Arquivo | Mecanismo |
|---|---|
| `cenario1_simetrica.py` | AES-256 CBC |
| `cenario2_assinatura.py` | RSA + SHA-256 |
| `cenario3_troca_chaves.py` | RSA OAEP |
| `cenario4_hibrido.py` | Solução híbrida completa |

---

## 7. Explicação do Cenário 1 (AES-256) passo a passo
- `gerar_chave()` → 32 bytes aleatórios (256 bits)
- `cifrar_documento()` → gera IV + aplica padding + cifra com AES CBC
- `decifrar_documento()` → decifra + remove padding → documento original

---

## 8. Fluxo de decifragem detalhado
Explicação do processo inverso da cifragem:
1. Recria o Cipher com mesma chave e IV
2. Usa `.decryptor()` em vez de `.encryptor()`
3. Decifra os dados (ainda com padding)
4. Remove o padding → documento original

---

## 9. O que é AES
- Advanced Encryption Standard, criado em 2001 pelo NIST
- Baseado no algoritmo Rijndael de dois criptógrafos belgas
- Divide dados em blocos de 16 bytes e aplica rodadas de transformações matemáticas
- AES-256 usa 14 rodadas — nunca foi quebrado matematicamente

---

## 10. O que é o IV (Initialization Vector)
- Vetor de Inicialização — não é a variável `i` de loops
- 16 bytes aleatórios gerados a cada cifragem
- Garante que o mesmo documento cifrado duas vezes gere resultados diferentes
- Pode ser enviado junto com os dados cifrados sem risco — inútil sem a chave

---

## 11. IV como prática padrão com AES
Confirmação de que o IV é parte obrigatória do AES no modo CBC.
A sigla `iv` é convenção universal em todas as linguagens e bibliotecas de criptografia.

---

## 12. Modos do AES — o que é CBC
- AES puro cifra apenas 1 bloco de 16 bytes por vez
- Os modos definem como os blocos se relacionam entre si
- **CBC** (Cipher Block Chaining): cada bloco cifrado depende do anterior, eliminando padrões
- Outros modos: ECB (inseguro), GCM (mais moderno, verifica integridade), CTR (mais rápido)
- GCM seria a escolha ideal em produção

---

## 13. O que é RSA
- Rivest, Shamir e Adleman — criado em 1977
- Baseado na dificuldade de fatorar números primos enormes
- Chave de 2048 bits: fatorar levaria milhares de anos com computadores atuais
- Limitação: só cifra até ~245 bytes — por isso não cifra documentos, apenas a chave AES

---

## 14. Cenário 2 usa criptografia assimétrica?
Confirmação: o cenário 2 usa exclusivamente RSA (assimétrica).
- Assinar → chave privada do remetente
- Verificar → chave pública do remetente
- Documento adulterado → hash SHA-256 muda → assinatura inválida

---

## 15. Explicação do problema da troca de chaves (Cenário 3)
Problema teórico: como entregar a chave AES sem expô-la na rede?
Solução: RSA OAEP cifra a chave AES com a chave pública do destinatário.
Somente o destinatário (dono da chave privada) consegue decifrar a chave AES.

---

## 16. Explicação do Cenário 4 (Híbrido)
Fluxo de envio:
1. Gera chave AES aleatória
2. Cifra o documento com AES
3. Cifra a chave AES com RSA público do destinatário
4. Assina o documento cifrado com RSA privado do remetente

Fluxo de recebimento:
1. Verifica assinatura → rejeita se inválida
2. Decifra chave AES com RSA privado
3. Decifra documento com AES

---

## 17. Revisão final dos requisitos
Todos os cenários da tarefa foram atendidos:
- C1 (transmissão) e C3 (armazenamento) → AES-256
- C2 (autoria) → RSA + SHA-256
- C4 (troca de chaves) → RSA OAEP
- Combinação → cenario4_hibrido.py

---

## 18. Documento de boas práticas
Gerado o arquivo `boas-praticas-seguranca.md` com orientações para a equipe sobre troca de chaves:
- Nunca compartilhar chaves por e-mail ou planilha
- Cada setor com seu próprio par de chaves
- Rotação periódica anual
- Armazenamento seguro da chave privada
- Registro de auditoria de uso

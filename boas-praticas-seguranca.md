# Boas Práticas de Segurança — Troca de Chaves

## Por que isso é um problema humano?

A criptografia protege os dados, mas não protege contra erros humanos.
Uma chave vazada por descuido invalida qualquer proteção técnica implementada.

---

## O que NÃO fazer

- **Nunca** enviar chaves por e-mail, WhatsApp ou planilhas compartilhadas
- **Nunca** usar a mesma chave para todos os setores
- **Nunca** armazenar chaves em texto claro no servidor
- **Nunca** compartilhar chave privada com outra pessoa, mesmo que seja um colega de setor

---

## O que fazer

### 1. Cada setor tem seu próprio par de chaves
Cada departamento (RH, Jurídico, Financeiro) gera seu próprio par de chaves RSA.
A chave privada fica na máquina do setor. A chave pública é registrada em um diretório central.

### 2. Rotação periódica de chaves
Chaves devem ser trocadas periodicamente — recomendado a cada 12 meses.
Em caso de suspeita de vazamento, trocar imediatamente.

### 3. Armazenamento seguro da chave privada
A chave privada nunca deve ficar em texto claro.
O ideal é protegê-la com uma senha forte ou armazená-la em um cofre de segredos (ex: HashiCorp Vault, AWS Secrets Manager).

### 4. Registro de uso (auditoria)
Todo acesso ou uso de chave deve ser registrado com data, hora e responsável.
Isso permite identificar usos indevidos rapidamente.

### 5. Acesso mínimo necessário
Um setor só deve ter acesso à chave pública de quem realmente precisa se comunicar.
O Financeiro não precisa da chave pública do RH se nunca trocam documentos.

---

## Resumo

| Ação | Permitido |
|---|---|
| Enviar chave privada por e-mail | Nunca |
| Compartilhar chave pública abertamente | Sim |
| Usar a mesma chave por anos | Não |
| Armazenar chave privada sem proteção | Nunca |
| Registrar uso das chaves | Sempre |

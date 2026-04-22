"""
Cenario 4 - Solucao Hibrida Completa
Combina: AES-256 (simetrica) + RSA (assimetrica) + SHA-256 (assinatura digital)

Fluxo de envio (remetente):
  1. Gera uma chave AES aleatoria
  2. Cifra o documento com AES (confidencialidade)
  3. Cifra a chave AES com a chave publica RSA do destinatario (troca segura)
  4. Assina o documento cifrado com sua chave privada RSA (autoria + integridade)

Fluxo de recepcao (destinatario):
  1. Verifica a assinatura do remetente (confirma autoria e integridade)
  2. Decifra a chave AES com sua chave privada RSA
  3. Decifra o documento com a chave AES recuperada
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.exceptions import InvalidSignature
import os


# ── Geracao de chaves ────────────────────────────────────────────────────────

def gerar_par_chaves_rsa():
    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return chave_privada, chave_privada.public_key()


# ── AES-256 ──────────────────────────────────────────────────────────────────

def _cifrar_aes(chave: bytes, dados: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    dados_padded = padder.update(dados) + padder.finalize()
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    enc = cipher.encryptor()
    return iv, enc.update(dados_padded) + enc.finalize()


def _decifrar_aes(chave: bytes, iv: bytes, dados_cifrados: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    dec = cipher.decryptor()
    dados_padded = dec.update(dados_cifrados) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(dados_padded) + unpadder.finalize()


# ── RSA: cifrar/decifrar chave simetrica ─────────────────────────────────────

def _cifrar_chave_rsa(chave_publica, chave_aes: bytes) -> bytes:
    return chave_publica.encrypt(
        chave_aes,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _decifrar_chave_rsa(chave_privada, chave_cifrada: bytes) -> bytes:
    return chave_privada.decrypt(
        chave_cifrada,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ── Assinatura digital ───────────────────────────────────────────────────────

def _assinar(chave_privada, dados: bytes) -> bytes:
    return chave_privada.sign(
        dados,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _verificar_assinatura(chave_publica, dados: bytes, assinatura: bytes) -> bool:
    try:
        chave_publica.verify(
            assinatura,
            dados,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ── Fluxo principal ──────────────────────────────────────────────────────────

def enviar_documento(documento: bytes, chave_privada_remetente, chave_publica_destinatario) -> dict:
    """Prepara o pacote seguro para envio."""
    chave_aes = os.urandom(32)
    iv, documento_cifrado = _cifrar_aes(chave_aes, documento)
    chave_aes_cifrada = _cifrar_chave_rsa(chave_publica_destinatario, chave_aes)
    assinatura = _assinar(chave_privada_remetente, documento_cifrado)

    return {
        "documento_cifrado": documento_cifrado,
        "iv": iv,
        "chave_aes_cifrada": chave_aes_cifrada,
        "assinatura": assinatura,
    }


def receber_documento(pacote: dict, chave_privada_destinatario, chave_publica_remetente) -> bytes | None:
    """Verifica, decifra e retorna o documento original."""
    assinatura_valida = _verificar_assinatura(
        chave_publica_remetente,
        pacote["documento_cifrado"],
        pacote["assinatura"],
    )

    if not assinatura_valida:
        print("ALERTA: Assinatura invalida — documento rejeitado.")
        return None

    chave_aes = _decifrar_chave_rsa(chave_privada_destinatario, pacote["chave_aes_cifrada"])
    return _decifrar_aes(chave_aes, pacote["iv"], pacote["documento_cifrado"])


# ── Demonstracao ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Gerando chaves RSA para RH (remetente) e Juridico (destinatario) ===")
    chave_priv_rh, chave_pub_rh = gerar_par_chaves_rsa()
    chave_priv_juridico, chave_pub_juridico = gerar_par_chaves_rsa()

    documento_original = b"Contrato de trabalho - Joao Silva - R$ 12.000,00 - Confidencial"
    print(f"\nDocumento original: {documento_original.decode()}")

    print("\n--- Enviando documento (RH → Juridico) ---")
    pacote = enviar_documento(documento_original, chave_priv_rh, chave_pub_juridico)
    print(f"Documento cifrado : {pacote['documento_cifrado'].hex()[:60]}...")
    print(f"Assinatura        : {pacote['assinatura'].hex()[:60]}...")

    print("\n--- Recebendo documento (Juridico) ---")
    documento_recebido = receber_documento(pacote, chave_priv_juridico, chave_pub_rh)

    if documento_recebido:
        print(f"Documento decifrado: {documento_recebido.decode()}")
        print(f"\nDocumento integro e autentico: {documento_original == documento_recebido}")

    print("\n--- Teste com assinatura adulterada ---")
    pacote_adulterado = dict(pacote)
    pacote_adulterado["assinatura"] = os.urandom(len(pacote["assinatura"]))
    receber_documento(pacote_adulterado, chave_priv_juridico, chave_pub_rh)

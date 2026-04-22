"""
Cenario 3 - Troca Segura de Chaves
Mecanismo: RSA com padding OAEP para cifrar a chave simetrica

Problema resolvido:
- A criptografia simetrica exige que ambos os lados tenham a mesma chave
- Enviar a chave pela rede sem protecao e um risco critico
- Solucao: cifrar a chave AES com a chave publica RSA do destinatario
  → Somente o destinatario (dono da chave privada) consegue decifrar
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os


def gerar_par_chaves():
    """Gera um par de chaves RSA 2048 bits para o destinatario."""
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return chave_privada, chave_privada.public_key()


def cifrar_chave_simetrica(chave_publica_destinatario, chave_simetrica: bytes) -> bytes:
    """
    Remetente cifra a chave AES com a chave publica do destinatario.
    OAEP e o padding seguro recomendado para cifragem RSA.
    """
    return chave_publica_destinatario.encrypt(
        chave_simetrica,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decifrar_chave_simetrica(chave_privada_destinatario, chave_cifrada: bytes) -> bytes:
    """Destinatario decifra a chave AES usando sua chave privada."""
    return chave_privada_destinatario.decrypt(
        chave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


if __name__ == "__main__":
    chave_privada_juridico, chave_publica_juridico = gerar_par_chaves()

    chave_aes_original = os.urandom(32)
    print(f"Chave AES gerada       : {chave_aes_original.hex()}")

    chave_aes_cifrada = cifrar_chave_simetrica(chave_publica_juridico, chave_aes_original)
    print(f"Chave AES cifrada      : {chave_aes_cifrada.hex()[:60]}...")

    chave_aes_recuperada = decifrar_chave_simetrica(chave_privada_juridico, chave_aes_cifrada)
    print(f"Chave AES recuperada   : {chave_aes_recuperada.hex()}")

    print(f"\nChave transmitida com sucesso: {chave_aes_original == chave_aes_recuperada}")

"""
Cenario 1 - Protecao do conteudo dos documentos
Mecanismo: Criptografia Simetrica (AES-256 modo CBC)

Por que AES-256?
- Padrao de mercado para cifrar grandes volumes de dados
- Muito mais rapido que criptografia assimetrica
- Chave de 256 bits oferece altissimo nivel de seguranca
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def gerar_chave() -> bytes:
    """Gera uma chave aleatoria de 256 bits (32 bytes)."""
    return os.urandom(32)


def cifrar_documento(chave: bytes, documento: bytes) -> tuple[bytes, bytes]:
    """
    Cifra o conteudo do documento com AES-256 CBC.
    Retorna (iv, dados_cifrados).
    O IV (vetor de inicializacao) garante que o mesmo texto gere cifras diferentes a cada vez.
    """
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    dados_padded = padder.update(documento) + padder.finalize()

    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    dados_cifrados = encryptor.update(dados_padded) + encryptor.finalize()

    return iv, dados_cifrados


def decifrar_documento(chave: bytes, iv: bytes, dados_cifrados: bytes) -> bytes:
    """Decifra o documento usando a mesma chave e IV usados na cifragem."""
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dados_padded = decryptor.update(dados_cifrados) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dados_padded) + unpadder.finalize()


if __name__ == "__main__":
    documento_original = b"Contrato confidencial - Salario: R$ 15.000,00"
    print(f"Documento original : {documento_original.decode()}")

    chave = gerar_chave()
    iv, documento_cifrado = cifrar_documento(chave, documento_original)
    print(f"Documento cifrado  : {documento_cifrado.hex()}")

    documento_recuperado = decifrar_documento(chave, iv, documento_cifrado)
    print(f"Documento decifrado: {documento_recuperado.decode()}")

    print(f"\nIntegridade mantida: {documento_original == documento_recuperado}")

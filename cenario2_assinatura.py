"""
Cenario 2 - Garantia de Autoria e Integridade
Mecanismo: Assinatura Digital (RSA 2048 bits + SHA-256)

Como funciona:
- Remetente assina o documento com sua chave PRIVADA
- Destinatario verifica a assinatura com a chave PUBLICA do remetente
- SHA-256 gera um hash do documento — qualquer alteracao invalida a assinatura
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def gerar_par_chaves():
    """Gera um par de chaves RSA 2048 bits (chave_privada, chave_publica)."""
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return chave_privada, chave_privada.public_key()


def assinar_documento(chave_privada, documento: bytes) -> bytes:
    """
    Assina o documento com a chave privada do remetente.
    PSS e o padding recomendado para assinaturas RSA modernas.
    """
    return chave_privada.sign(
        documento,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verificar_assinatura(chave_publica, documento: bytes, assinatura: bytes) -> bool:
    """
    Verifica se a assinatura e valida para o documento e a chave publica informados.
    Retorna True se autentico e integro, False caso contrario.
    """
    try:
        chave_publica.verify(
            assinatura,
            documento,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    chave_privada_rh, chave_publica_rh = gerar_par_chaves()

    documento = b"Parecer interno: aprovado para promocao - RH"
    print(f"Documento: {documento.decode()}")

    assinatura = assinar_documento(chave_privada_rh, documento)
    print(f"Assinatura gerada: {assinatura.hex()[:60]}...")

    valido = verificar_assinatura(chave_publica_rh, documento, assinatura)
    print(f"\nAssinatura valida (documento original): {valido}")

    documento_adulterado = b"Parecer interno: REPROVADO para promocao - RH"
    valido_adulterado = verificar_assinatura(chave_publica_rh, documento_adulterado, assinatura)
    print(f"Assinatura valida (documento adulterado): {valido_adulterado}")

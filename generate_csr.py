
from cryptography import x509
from cryptography.x509 import Name, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def generate_csr(client_common_name):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SC"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lages"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IFSC"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_common_name),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256())

    os.makedirs("csr", exist_ok=True)
    key_path = f"csr/{client_common_name}_private_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    csr_path = f"csr/{client_common_name}_request.csr"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"✔️ CSR gerado em {csr_path}")
    print(f"✔️ Chave privada salva em {key_path}")
    return csr_path, key_path

if __name__ == "__main__":
    client_name = input("Digite o nome (Common Name) para o CSR: ").strip()
    generate_csr(client_name)

"""KVKK: TC kimlik no / telefon gibi alanları veritabanında şifreli saklamak ve API yanıtında maskelemek için yardımcılar.

Kurulum:
  1. requirements.txt'e `cryptography` ekle
  2. Anahtar üret:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  3. Render ortam değişkeni olarak PII_ENCRYPTION_KEY=<üretilen anahtar> tanımla (repoya YAZMA, kaybetme:
     kaybedersen şifreli veriler okunamaz).
"""
import os
from cryptography.fernet import Fernet, InvalidToken

_PREFIX = "enc:v1:"
_fernet = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.environ.get("PII_ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("PII_ENCRYPTION_KEY tanımlı değil")
        _fernet = Fernet(key.encode())
    return _fernet


def check_config() -> None:
    """Uygulama açılırken çağır: anahtar yoksa ya da bozuksa hemen hata versin."""
    _get_fernet()


def encrypt_pii(value: str) -> str:
    if not value or value.startswith(_PREFIX):
        return value
    return _PREFIX + _get_fernet().encrypt(value.encode()).decode()


def decrypt_pii(value: str) -> str:
    """Şifreli değeri çözer. Eski (düz metin) kayıtlar olduğu gibi döner."""
    if not value or not value.startswith(_PREFIX):
        return value
    try:
        return _get_fernet().decrypt(value[len(_PREFIX):].encode()).decode()
    except InvalidToken as e:
        raise RuntimeError("PII verisi çözülemedi (anahtar değişmiş olabilir)") from e


def is_masked(value: str) -> bool:
    return isinstance(value, str) and "*" in value


def mask_identity(value: str) -> str:
    """12345678901 -> *******8901"""
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def mask_phone(value: str) -> str:
    """+905321234567 -> +90********67"""
    if not value:
        return ""
    if len(value) <= 5:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 5) + value[-2:]


def protect(new_value: str, stored_value: str = "") -> str:
    """PUT sırasında kullanılır. Kullanıcı maskeli değeri değiştirmediyse eski (şifreli) kaydı korur,
    yeni değer geldiyse şifreleyip döner."""
    if is_masked(new_value):
        return stored_value or ""
    return encrypt_pii(new_value)

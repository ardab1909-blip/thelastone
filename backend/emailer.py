import os
import smtplib
from email.message import EmailMessage
from html import escape
import logging

logger = logging.getLogger(__name__)

MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", MAIL_USERNAME)
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "Weird Studio")

def configured() -> bool:
    return bool(MAIL_SERVER and MAIL_USERNAME and MAIL_PASSWORD)

def _otp_template(code: str, purpose: str) -> tuple[str, str]:
    brand = escape(EMAIL_FROM_NAME)
    if purpose == "reset":
        subject = f"{EMAIL_FROM_NAME} şifre sıfırlama kodun"
        intro = "Şifreni sıfırlamak için aşağıdaki kodu uygulamadaki alana gir."
    else:
        subject = f"{EMAIL_FROM_NAME} doğrulama kodun"
        intro = "Hesabını etkinleştirmek için aşağıdaki kodu uygulamadaki alana gir."
    
    html = (
        '<table role="presentation" width="100%" style="background:#07080c;padding:32px 0"><tr><td align="center">'
        '<table role="presentation" width="480" style="background:#10131c;border:1px solid #1f2430;border-radius:16px;'
        'padding:32px;font-family:Arial,sans-serif;color:#e6e9f2">'
        f'<tr><td style="font-size:12px;letter-spacing:4px;color:#00f2fe">{brand} · STREAM DECK PRO</td></tr>'
        f'<tr><td style="padding-top:16px;font-size:15px;line-height:1.5">{escape(intro)} Kod 10 dakika geçerlidir.</td></tr>'
        f'<tr><td style="padding:24px 0;font-size:36px;letter-spacing:12px;font-weight:bold;color:#00f2fe;text-align:center">{escape(code)}</td></tr>'
        '<tr><td style="font-size:12px;color:#8b93a7;line-height:1.5">Bu işlemi sen başlatmadıysan bu e-postayı yok sayabilirsin. '
        f'{brand} senden hiçbir zaman şifreni veya kart bilgilerini e-posta ile istemez.</td></tr>'
        f'<tr><td style="padding-top:20px;font-size:11px;color:#565e72">Gönderen: {brand}</td></tr>'
        "</table></td></tr></table>"
    )
    return subject, html

async def send_email(*, to: str, subject: str, html: str) -> bool:
    if not configured():
        raise ValueError("SMTP is not configured in environment variables.")
    
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{EMAIL_FROM_NAME} <{MAIL_FROM}>"
    msg["To"] = to
    msg.set_content("Lütfen HTML destekleyen bir e-posta istemcisi kullanın.")
    msg.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error("SMTP email send failed for %s: %s", to, e)
        raise e

async def send_otp(to: str, code: str, purpose: str) -> bool:
    """Returns True if the email was successfully sent via custom SMTP."""
    if not configured():
        return False
    subject, html = _otp_template(code, purpose)
    try:
        await send_email(to=to, subject=subject, html=html)
        return True
    except Exception as e:
        logger.error("OTP email send failed for %s: %s", to, e)
        return False
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from random import choices
from string import ascii_lowercase, digits

from config import SMTP_SERVER, SMTP_PORT, EMAIL, EMAIL_LOGIN, EMAIL_PASSWORD

def send_email(email, code):
    server = SMTP_SERVER
    port = SMTP_PORT
    from_email = EMAIL

    msg = MIMEMultipart()
    msg['From'] = formataddr(('CM', from_email))
    msg['To'] = email
    msg['Subject'] = 'Подтверждение регистрации'

    body = f'Благодарим за регистрацию!\nКод подтверждения: {code}\n'
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL(server, port) as server:
            server.login(EMAIL_LOGIN, EMAIL_PASSWORD)
            server.send_message(msg)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': e}

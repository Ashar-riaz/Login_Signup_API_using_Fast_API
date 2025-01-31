import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from utils import generate_reset_token

SENDER_EMAIL = "evadigitalhuman@gmail.com"
SENDER_PASSWORD = "obzi nwux rogo pxli"

# ✅ Send reset email
def send_reset_email(receiver_email: str):
    token = generate_reset_token(receiver_email)
    reset_link = f"http://localhost:3000/reset-password?token={token}"

    subject = "Password Reset Request"
    body = f"Click the link to reset your password: {reset_link}"

    # ✅ Email structure
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)  # Use Gmail SMTP
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

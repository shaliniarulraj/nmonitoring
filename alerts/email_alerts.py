import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv

load_dotenv()

def send_email(subject, body):
    message = Mail(
        from_email=os.getenv('EMAIL_USER'),
        to_emails=os.getenv('ADMIN_EMAIL'),
        subject=subject,
        plain_text_content=body
    )
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(f"Email sent: {response.status_code}")
    except Exception as e:
        print(f"Failed to send email: {e}")

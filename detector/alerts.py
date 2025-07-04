alerts = []

# --- Email Notification Config ---
EMAIL_ENABLED = True  # Set to False to disable email notifications
EMAIL_USER = 'your_email@gmail.com'  # Replace with your Gmail address
EMAIL_PASSWORD = 'your_app_password'  # Use an app password for Gmail
EMAIL_TO = 'recipient_email@gmail.com'  # Where to send alerts

try:
    import yagmail
    yag = yagmail.SMTP(EMAIL_USER, EMAIL_PASSWORD)
except Exception as e:
    yag = None
    EMAIL_ENABLED = False


def send_email_alert(subject, body):
    if EMAIL_ENABLED and yag:
        try:
            yag.send(EMAIL_TO, subject, body)
        except Exception as e:
            print(f"Failed to send email: {e}")


def add_alert(message):
    alerts.append(message)
    # Send email notification
    send_email_alert("[DoS/DDoS Detector Alert]", message)

def get_alerts():
    return alerts[-5:]  # Show last 5 alerts 
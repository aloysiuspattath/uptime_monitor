import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging

# Configure logging
logging.basicConfig(filename='email_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def send_email(receiver_email, subject, body):
    # Email configuration
    # Replace both email and password for smtp(GMAIL)
    sender_email = "your email id for smtp"
    password = "password for stmp"
    
    # Create message container - the correct MIME type is multipart/alternative
    msg = MIMEMultipart('alternative')
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    
    # Create the body of the message (a plain-text and an HTML version)
    text = f"Hi,\n{body}"
    html = f"""\
    <html>
      <body>
        <p>Hi,<br>
           {body}
        </p>
      </body>
    </html>
    """
    
    # Record the MIME types of both parts - text/plain and text/html
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    
    # Attach parts into message container
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        # Create SMTP session
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, password)  # Login with credentials
            server.sendmail(sender_email, receiver_email, msg.as_string())  # Send the message
            logger.info(f"Email sent successfully to {receiver_email}.")
    except Exception as e:
        logger.error(f"Error sending email to {receiver_email}: {e}")

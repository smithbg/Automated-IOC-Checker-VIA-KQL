from email.message import EmailMessage
import ssl
import smtplib
from constants import email_sender, email_password, email_reciver

def findings_email_notify(): 
    sender = email_sender
    password = email_password
    reciver= email_reciver

    subject = "SECURITY ALERT"

    body= "A SECURITY ALERT WAS FOUND ON YOUR MACHINCE PLEASE VIST THIS LINK TO LOOK DEEPER: https://portal.azure.com/#@smithbgLLC.onmicrosoft.com/resource/subscriptions/2beae933-5961-400e-b91f-6c0fff0f2354/resourceGroups/project/providers/Microsoft.OperationalInsights/workspaces/porject/Tables "

    email = EmailMessage()

    email['From'] = sender
    email['To'] = reciver
    email['Subject'] = subject
    email.set_content(body)

    security =ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=security) as smtp:
        smtp.login(sender, password)
        smtp.sendmail(sender, reciver, email.as_string())

def No_findings_email_notify(): 
    sender = email_sender
    password = email_password
    reciver= email_reciver

    subject = "IOC Daily Automation"

    body= "The query returned no resutlts today"

    email = EmailMessage()

    email['From'] = sender
    email['To'] = reciver
    email['Subject'] = subject
    email.set_content(body)

    security =ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=security) as smtp:
        smtp.login(sender, password)
        smtp.sendmail(sender, reciver, email.as_string())
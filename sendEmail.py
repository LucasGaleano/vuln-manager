from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

def send_email_report(emailFrom, emailTo, subject, mailServer, reportName, reportOptionalName=None, type=None):

    if not reportOptionalName:
        reportOptionalName = reportName


    attachmentPath = "./"+reportName+"."+type

    msg = ''
    msg += f"Subject: {subject}\n"

    message = MIMEMultipart('mixed')
    message['From'] = emailFrom
    message['To'] = emailTo
    message['Subject'] = subject

    with open(attachmentPath, "rb") as attachment:
        p = MIMEApplication(attachment.read(),_subtype=type)
        p.add_header('Content-Disposition', "attachment; filename= %s" %reportOptionalName)
        message.attach(p)

    server = SMTP(host=mailServer, port=25)
    server.starttls()
    server.send_message(message)
    server.quit()

def send_email_plain(emailFrom, emailTo, subject, mailServer, content):
    
    msg = ''
    msg += f"Subject: {subject}\n"
    msg += content

    server = SMTP(host=mailServer, port=25)
    server.starttls() 
    server.sendmail(emailFrom, emailTo, msg)
    server.quit()



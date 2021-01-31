#!/usr/bin/env python3
import smtplib
import dns.resolver
import sys
from email.message import EmailMessage

def get_mailservers(domain):
    mxresult = dns.resolver.resolve(domain, 'MX')
    for r in sorted(mxresult, key=lambda r: r.preference):
        yield r.exchange.to_text().rstrip('.')


def parse_args():
    from argparse import ArgumentParser
    ap = ArgumentParser()
    ap.add_argument('--from', dest='mailfrom', required=True)
    ap.add_argument('--to', dest='mailto', required=True)
    ap.add_argument('--subject')
    return ap.parse_args()


def main():
    args = parse_args()

    # Build the message
    msg = EmailMessage()
    msg.set_content(sys.stdin.read())

    msg['Subject'] = args.subject
    msg['From'] = args.mailfrom
    msg['To'] = args.mailto

    print("\nMessage:\n")
    print(msg)
    print()

    # Look up mailservers
    username, domain = args.mailto.split('@')
    mailsrvs = list(get_mailservers(domain))

    # Try to send!
    for hostname in mailsrvs:
        print("Trying mailserver {}".format(hostname))

        with smtplib.SMTP(hostname) as smtp:
            print("  Starting TLS:")
            print(smtp.starttls())
            print("  EHLO again:")
            print(smtp.ehlo())
            print("  NOOP:")
            print(smtp.noop())

            print("  Sending message!")
            print(smtp.send_message(msg))

            print("  Quit:")
            print(smtp.quit())

        break

main()

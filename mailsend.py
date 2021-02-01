#!/usr/bin/env python3
import smtplib
import dns.resolver
import sys
from email.message import EmailMessage
import logging
import socket
import ssl

logger = logging.getLogger(__name__)

def get_mailservers(domain):
    mxresult = dns.resolver.query(domain, 'MX')
    for r in sorted(mxresult, key=lambda r: r.preference):
        yield r.exchange.to_text().rstrip('.')


def send_email(mailsrv, sslctx, msg):
    with smtplib.SMTP(mailsrv) as smtp:
        logger.debug("Issuing STARTTLS")
        r = smtp.starttls(context=sslctx)
        logger.debug("STARTTLS response: {}".format(r))

        logger.debug("Sending message")
        smtp.send_message(msg)

        logger.debug("Issuing QUIT")
        r = smtp.quit()
        logger.debug("QUIT response: {}".format(r))


def parse_args():
    DEFAULT_LOGLEVEL = 'WARNING'

    from argparse import ArgumentParser
    ap = ArgumentParser()
    ap.add_argument('--from', dest='mailfrom', required=True)
    ap.add_argument('--to', dest='mailto', required=True)
    ap.add_argument('--subject')
    ap.add_argument('--loglevel', type=str.upper,
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default=DEFAULT_LOGLEVEL,
            help='Set the logging level (default: {})'.format(DEFAULT_LOGLEVEL))

    grp = ap.add_mutually_exclusive_group()
    grp.add_argument('--server', default="localhost",
            help="SMTP server to connect to")
    grp.add_argument('--resolve', action="store_true",
            help="Find SMTP server by recipient domain MX record")

    return ap.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(level=args.loglevel)

    # Build the message
    msg = EmailMessage()
    msg.set_content(sys.stdin.read())

    msg['From'] = args.mailfrom
    msg['To'] = args.mailto
    if args.subject:
        msg['Subject'] = args.subject

    logger.info("Message:\n{}".format(msg))

    if args.resolve:
        # Look up mailservers
        _, domain = args.mailto.split('@')
        mailsrvs = list(get_mailservers(domain))
    else:
        mailsrvs = [args.server]

    sslctx = ssl.create_default_context()

    # Try to send!
    for hostname in mailsrvs:
        logger.info("Trying mailserver {}".format(hostname))

        try:
            send_email(hostname, sslctx, msg)
        except (ConnectionRefusedError, socket.error):
            logger.exception("Error connecting to SMTP server")
        except ssl.SSLError:
            logger.exception("SSL Error")
        except smtplib.SMTPException:
            logger.exception("Error sending message")
        else:
            break
    else:
        raise SystemExit("No more servers to try!")

main()

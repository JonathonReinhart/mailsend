#!/usr/bin/env python3
import smtplib
import dns.resolver
import sys
from email.message import EmailMessage
import logging
import socket
import ssl
from enum import Enum

logger = logging.getLogger(__name__)

class TLSMode(Enum):
    NONE = 'none'
    STARTTLS = 'starttls'
    ALWAYS = 'always'

    def __str__(self):
        return self.value


def get_mailservers(domain):
    mxresult = dns.resolver.query(domain, 'MX')
    for r in sorted(mxresult, key=lambda r: r.preference):
        yield r.exchange.to_text().rstrip('.')


def send_email(mailsrv, message, tls_mode=TLSMode.NONE, sslctx=None, username=None, password=None):

    if tls_mode == TLSMode.ALWAYS:
        raise NotImplementedError()

    with smtplib.SMTP(mailsrv) as smtp:
        if tls_mode == TLSMode.STARTTLS:
            logger.debug("Issuing STARTTLS")
            r = smtp.starttls(context=sslctx)
            logger.debug("STARTTLS response: {}".format(r))

        if username is not None:
            logger.debug("Logging in")
            smtp.login(user=username, password=password)

        logger.debug("Sending message")
        smtp.send_message(message)

        logger.debug("Issuing QUIT")
        r = smtp.quit()
        logger.debug("QUIT response: {}".format(r))


def parse_args():
    DEFAULT_LOGLEVEL = 'WARNING'
    DEFAULT_TLS_MODE = 'starttls'

    from argparse import ArgumentParser
    ap = ArgumentParser()
    ap.add_argument('--from', dest='mailfrom', required=True)
    ap.add_argument('--to', dest='mailto', required=True)
    ap.add_argument('--subject')
    ap.add_argument('--loglevel', type=str.upper,
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default=DEFAULT_LOGLEVEL,
            help='Set the logging level (default: {})'.format(DEFAULT_LOGLEVEL))

    # Server selection
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument('--server', default="localhost",
            help="SMTP server to connect to")
    grp.add_argument('--resolve', action="store_true",
            help="Find SMTP server by recipient domain MX record")

    # TLS Settings
    ap.add_argument('--tls',
            choices = TLSMode,
            default=DEFAULT_TLS_MODE,
            type=TLSMode,
            help="TLS mode (default: {})".format(DEFAULT_TLS_MODE))
    ap.add_argument('--no-verify', action='store_true',
            help="Don't verify TLS server certificate (for testing only!)")

    # Authentication
    ap.add_argument('--auth-username',
            help="User to authenticate as (will prompt for password)")

    return ap.parse_args()


def get_ssl_context(args):
    sslctx = ssl.create_default_context()

    if args.no_verify:
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE

    return sslctx


def main():
    args = parse_args()
    logging.basicConfig(level=args.loglevel)

    # Prompt for password if username is given
    password = None
    if args.auth_username is not None:
        import getpass
        password = getpass.getpass()

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


    # Try to send!
    for hostname in mailsrvs:
        logger.info("Trying mailserver {}".format(hostname))

        try:
            send_email(mailsrv=hostname,
                       message=msg,
                       tls_mode=args.tls,
                       sslctx=get_ssl_context(args),
                       username=args.auth_username,
                       password=password,
                       )
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

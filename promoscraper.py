import imaplib
import email
import re
from datetime import datetime, timedelta
from email.header import decode_header
from email.utils import getaddresses
import csv
import quopri
import argparse

# Configuration (Edit these values)
EMAIL = 'test@gmail.com'
APP_PASSWORD = 'xxxx xxxx xxxx xxxx'
OUTPUT_FILE = 'results.csv'  # Output CSV filename
IMAP_SERVER = 'imap.gmail.com'
IMAP_PORT = 993

def decode_mime(s):
    """Decode MIME encoded string"""
    decoded = []
    for part, encoding in decode_header(s):
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(encoding or 'utf-8', errors='replace'))
            except:
                decoded.append(part.decode('latin-1', errors='replace'))
        else:
            decoded.append(part)
    return ' '.join(decoded)

def clean_text(text):
    """Normalize text for pattern matching"""
    # Remove everything except letters & numbers, uppercase
    return re.sub(r'[^A-Za-z0-9]', '', text or '').upper()

def get_email_body(msg):
    """Extract and decode email body content"""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "").lower()
            if "attachment" in content_disposition:
                continue
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'
                if content_type in ('text/plain', 'text/html') and payload:
                    # handle quoted-printable
                    if part.get('Content-Transfer-Encoding', '').lower() == 'quoted-printable':
                        payload = quopri.decodestring(payload)
                    body_parts.append(payload.decode(charset, errors='replace'))
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            if payload:
                body_parts.append(payload.decode(charset, errors='replace'))
        except Exception:
            pass
    return '\n'.join(body_parts)

def find_code_pattern(text, search_string):
    """Find the search_string in text allowing for spaces/special chars"""
    # escape and then allow any characters between each character
    escaped = re.escape(search_string.upper())
    pattern = r'\s*'.join(list(escaped))
    return re.search(pattern, text, re.IGNORECASE)

def main(days_back, search_string):
    # 1) connect & login
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL, APP_PASSWORD)
    mail.select('inbox')

    # 2) build date filter
    date_since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")

    # 3) search ALL emails since that date
    search_criteria = f'(SINCE "{date_since}")'
    status, data = mail.search(None, search_criteria)
    if status != 'OK':
        print("❌ Error searching emails")
        return

    email_ids = data[0].split()
    total = len(email_ids)
    print(f"🔍 Found {total} emails since {date_since}. Searching now...")

    results = []

    # 4) fetch and scan each email
    for eid in email_ids:
        try:
            st, msg_data = mail.fetch(eid, '(RFC822)')
            if st != 'OK':
                continue

            msg = email.message_from_bytes(msg_data[0][1])

            # parse all addresses in To:
            to_hdr = msg.get('To', '')
            recipients = [addr.lower() for _, addr in getaddresses([to_hdr]) if addr]
            if not recipients:
                continue

            # extract & clean body
            body = get_email_body(msg)
            cleaned = clean_text(body)

            # look for the code
            if find_code_pattern(cleaned, search_string):
                for r in recipients:
                    results.append([r, search_string.upper()])

        except Exception as e:
            print(f"⚠️  Error processing email {eid.decode()}: {e}")
            continue

    # 5) write CSV
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['email_address', 'code_found'])
        writer.writerows(results)

    # 6) summary
    print(f"✅ Searched {total} emails. Found {len(results)} matches.")
    print(f"📄 Results saved to {OUTPUT_FILE}")

    mail.close()
    mail.logout()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find promo codes in emails')
    parser.add_argument('--days', type=int, required=True, help='Number of days to search back')
    parser.add_argument('--code', type=str, required=True, help='Promo code to search for')
    args = parser.parse_args()

    main(args.days, args.code)

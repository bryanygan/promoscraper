#!/usr/bin/env python3
# test commit

import discord
from discord import app_commands
from discord.ext import commands
from typing import Optional
import imaplib
import email as email_module
import re
from datetime import datetime, timedelta
from email.header import decode_header
from email.utils import getaddresses, parsedate_to_datetime
import quopri
import sqlite3
from cryptography.fernet import Fernet
import asyncio
import os
import io
import time
import logging

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)

# Configuration
IMAP_SERVER = 'imap.gmail.com'
IMAP_PORT = 993
DATABASE_NAME = 'user_credentials.db'
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY').encode()

# Initialize Fernet for encryption
cipher_suite = Fernet(ENCRYPTION_KEY)

# Initialize Discord bot with required intents
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents)

# Database setup
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id TEXT PRIMARY KEY, email TEXT, app_password TEXT)''')
    conn.commit()
    conn.close()

init_db()

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password).decode()

async def store_credentials(user_id, email, app_password):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    encrypted_pw = encrypt_password(app_password)
    c.execute('INSERT OR REPLACE INTO users VALUES (?, ?, ?)', 
              (str(user_id), email, encrypted_pw))
    conn.commit()
    conn.close()

async def get_credentials(user_id):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('SELECT email, app_password FROM users WHERE user_id=?', (str(user_id),))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], decrypt_password(row[1])
    return None, None

# Command Tree Setup
@bot.tree.command(name="setcreds", description="Set your email and app password")
@app_commands.describe(
    email="Your email address",
    app_password="Your app-specific password (create one in your email account settings)"
)
async def set_credentials(interaction: discord.Interaction, email: str, app_password: str):
    """Set credentials using slash command"""
    await store_credentials(str(interaction.user.id), email, app_password)
    await interaction.response.send_message(
        "✅ Credentials stored securely!",
        ephemeral=True  # Only visible to the command user
    )

async def validate_credentials(email, app_password):
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(email, app_password)
        mail.logout()
        return True
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return False

@bot.tree.command(name="searchpromo", description="Search your inbox for promo codes")
@app_commands.describe(
    days_back="Number of days to search back",
    search_code="Promo code to look for"
)
async def search_promo(interaction: discord.Interaction, days_back: int, search_code: str):
    """Search for promo codes using slash command"""
    # Defer response while processing
    await interaction.response.defer()
    
    email, password = await get_credentials(str(interaction.user.id))
    
    if not email or not password:
        await interaction.followup.send(
            "❌ Please set your credentials first using /setcreds",
            ephemeral=True
        )
        return

    try:
        results = await search_emails(email, password, days_back, search_code)
        if results is None:
            await interaction.followup.send(
                "❌ Error accessing your inbox. Please check your credentials.",
                ephemeral=True
            )
            return
            
        if not results:
            await interaction.followup.send(
                "❌ No matching emails found.",
                ephemeral=True
            )
            return

        result_text = "\n".join(results)
        response_kwargs = {
            "content": f"✅ Found {len(results)} results:",
            "ephemeral": False  # Visible to everyone in the channel
        }

        if len(result_text) > 1900:
            response_kwargs["file"] = discord.File(
                io.StringIO(result_text), 
                filename="results.txt"
            )
        else:
            response_kwargs["content"] += f"\n```\n{result_text}\n```"

        await interaction.followup.send(**response_kwargs)

    except Exception as e:
        await interaction.followup.send(
            f"❌ Error during search: {str(e)}",
            ephemeral=True
        )

@bot.event
async def on_ready():
    # Allow /grab in DMs
    cmd = bot.tree.get_command("grab")
    if cmd:
        cmd.dm_permission = True

    # Sync globally (or to a guild) *after* toggling dm_permission
    await bot.tree.sync()
    print(f'Logged in as {bot.user} — commands synced!')
    print(f'Commands synced globally!')

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
                # handle quoted-printable
                if msg.get('Content-Transfer-Encoding', '').lower() == 'quoted-printable':
                    payload = quopri.decodestring(payload)
                body_parts.append(payload.decode(charset, errors='replace'))
        except Exception:
            pass
    return "\n".join(body_parts)

def find_code_pattern(text, code):
    """Return True if the normalized code appears in the text"""
    return bool(re.search(re.escape(code.upper()), text))

async def search_emails(email, app_password, days_back, search_code, subject_filter=None):
    loop = asyncio.get_event_loop()
    try:
        # Offload blocking IMAP connection to executor
        mail = await loop.run_in_executor(
            None,
            lambda: imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        )
        await loop.run_in_executor(None, mail.login, email, app_password)
        await loop.run_in_executor(None, mail.select, 'inbox')

        # Build optimized search query
        date_since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
        search_criteria = [f'SINCE "{date_since}"']
        
        if subject_filter:
            search_criteria.append(f'SUBJECT "{subject_filter}"')
            
        status, data = await loop.run_in_executor(
            None, 
            mail.search, 
            None, 
            ' '.join(search_criteria))  # Fixed parenthesis here
        
        if status != 'OK':
            return []

        email_ids = data[0].split()
        results = []

        for eid in email_ids:
            st, msg_data = await loop.run_in_executor(
                None, 
                mail.fetch, 
                eid, 
                '(BODY.PEEK[HEADER] RFC822.SIZE)'
            )
            if st != 'OK':
                continue

            msg = email_module.message_from_bytes(msg_data[0][1])
            to_hdr = msg.get('To', '')
            addresses = [addr for _, addr in getaddresses([to_hdr])]

            if not addresses:
                continue

            st, full_msg_data = await loop.run_in_executor(
                None,
                mail.fetch,
                eid,
                '(RFC822)'
            )
            if st != 'OK':
                continue

            msg = email_module.message_from_bytes(full_msg_data[0][1])
            body = get_email_body(msg)
            cleaned = clean_text(body)

            if find_code_pattern(cleaned, search_code):
                date_hdr = msg.get('Date', '')
                try:
                    sent_dt = parsedate_to_datetime(date_hdr)
                    expiry_dt = sent_dt + timedelta(days=14)
                    expiry_str = expiry_dt.strftime('%m-%d')
                except Exception:
                    expiry_str = 'unknown'

                for addr in addresses:
                    results.append(f"{addr} — expires {expiry_str}")

        await loop.run_in_executor(None, mail.close)
        await loop.run_in_executor(None, mail.logout)

        # Fixed dedupe syntax
        seen = set()
        return [x for x in results if not (x in seen or seen.add(x))]
        
    except Exception as e:  # This completes the try statement
        print(f"Search error: {str(e)}")
        return None

async def search_otp(
    user_email: str,
    app_password: str,
    target_addr: str,
    days_back: int = 1
) -> Optional[str]:
    """
    Search the last `days_back` days for the most recent message TO `target_addr`,
    then extract the 4-digit OTP from the <td class="p2b"> element.
    """
    loop = asyncio.get_event_loop()

    # connect off‐loop
    mail = await loop.run_in_executor(
        None, lambda: imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    )
    await loop.run_in_executor(None, mail.login, user_email, app_password)
    await loop.run_in_executor(None, mail.select, 'inbox')

    # search recent mail
    date_since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
    status, data = await loop.run_in_executor(
        None, mail.search, None, f'(SINCE "{date_since}")'
    )
    if status != 'OK':
        await loop.run_in_executor(None, mail.close)
        await loop.run_in_executor(None, mail.logout)
        return None

    otp: Optional[str] = None
    # scan newest→oldest
    for eid in reversed(data[0].split()):
        st, msg_data = await loop.run_in_executor(None, mail.fetch, eid, '(RFC822)')
        if st != 'OK':
            continue

        msg = email_module.message_from_bytes(msg_data[0][1])
        to_addrs = [addr for _, addr in getaddresses([msg.get('To', '')])]
        if target_addr not in to_addrs:
            continue

        body = get_email_body(msg)

        # HTML-based regex for the OTP cell
        m = re.search(
            r'<td[^>]*class=["\']p2b["\'][^>]*>\s*(\d{4})\s*</td>',
            body,
            flags=re.IGNORECASE
        )
        if m:
            otp = m.group(1)
            break

    # clean up
    await loop.run_in_executor(None, mail.close)
    await loop.run_in_executor(None, mail.logout)
    return otp


@bot.tree.command(
    name="searchselect",
    description="Search your inbox for the WELCOME25B promo code"
)
@app_commands.describe(
    days_back="How many days back to search (default 3)"
)
async def searchselect(interaction: discord.Interaction, days_back: int = 3):
    await interaction.response.defer()

    start_time = time.time()

    # Credentials
    user_email, password = await get_credentials(str(interaction.user.id))
    if not user_email or not password:
        return await interaction.followup.send(
            "❌ Please set your credentials first with `/setcreds`."
        )

    loop = asyncio.get_event_loop()
    mail = await loop.run_in_executor(
        None,
        lambda: imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    )
    await loop.run_in_executor(None, mail.login, user_email, password)
    await loop.run_in_executor(None, mail.select, 'INBOX')

    # Fast header search
    since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
    status, data = await loop.run_in_executor(
        None,
        mail.search,
        None,
        f'(SINCE "{since}" HEADER List-Id "uber-eats.3406847380.uber.com")'
    )
    if status != 'OK' or not data or not data[0]:
        await loop.run_in_executor(None, mail.close)
        await loop.run_in_executor(None, mail.logout)
        return await interaction.followup.send("❌ No matching emails found.")

    email_ids = data[0].split()
    total_searched = len(email_ids)
    results = []

    # Fetch only To & Date headers, build email — expires MM-DD
    for eid in email_ids:
        st, hdr = await loop.run_in_executor(
            None,
            mail.fetch,
            eid,
            '(BODY.PEEK[HEADER.FIELDS (To Date)])'
        )
        if st != 'OK' or not hdr or not hdr[0][1]:
            continue

        raw = hdr[0][1].decode('utf-8', errors='ignore')

        # extract only the To: line
        to_m = re.search(r'^To:\s*(.+)$', raw, flags=re.MULTILINE)
        if not to_m:
            continue
        to_addrs = [addr for _, addr in getaddresses([to_m.group(1)])]

        # extract Date: then compute expiry
        d_m = re.search(r'^Date:\s*(.+)$', raw, flags=re.MULTILINE)
        if not d_m:
            continue
        try:
            sent_dt = parsedate_to_datetime(d_m.group(1))
            exp_str = (sent_dt + timedelta(days=14)).strftime('%m-%d')
        except Exception:
            continue

        for addr in to_addrs:
            results.append(f"{addr} — expires {exp_str}")

    # Cleanup
    await loop.run_in_executor(None, mail.close)
    await loop.run_in_executor(None, mail.logout)

    # Log the count and duration to your terminal
    elapsed = time.time() - start_time
    logging.info(f"[searchselect] searched {total_searched} emails in {elapsed:.2f}s")

    if not results:
        return await interaction.followup.send("❌ No matching emails found.")

    # Send only the results
    output = "\n".join(results)
    if len(output) > 1900:
        await interaction.followup.send(
            file=discord.File(io.StringIO(output), filename="welcome25b_emails.txt")
        )
    else:
        await interaction.followup.send(output)

@bot.tree.command(
    name="usedchecker",
    description="Find which WELCOME25B accounts have later been updated/used"
)
@app_commands.describe(
    days_back="How many days back to look for promo emails (default 3)"
)
async def usedchecker(interaction: discord.Interaction, days_back: int = 3):
    await interaction.response.defer()
    start_time = time.time()

    # 1️⃣ Get creds
    user_email, password = await get_credentials(str(interaction.user.id))
    if not user_email or not password:
        return await interaction.followup.send(
            "❌ Please set your credentials first with `/setcreds`."
        )

    loop = asyncio.get_event_loop()
    mail = await loop.run_in_executor(
        None, lambda: imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    )
    await loop.run_in_executor(None, mail.login, user_email, password)
    await loop.run_in_executor(None, mail.select, "INBOX")

    # 2️⃣ Find all WELCOME25B promo emails by List-Id
    since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
    status, data = await loop.run_in_executor(
        None,
        mail.search,
        None,
        f'(SINCE "{since}" HEADER List-Id "uber-eats.3406847380.uber.com")'
    )
    if status != "OK" or not data or not data[0]:
        await loop.run_in_executor(None, mail.close)
        await loop.run_in_executor(None, mail.logout)
        return await interaction.followup.send("❌ No promo emails found.")

    promo_ids = data[0].split()

    # 3️⃣ Extract each forwarded-to address
    addrs = set()
    for eid in promo_ids:
        st, hdr = await loop.run_in_executor(
            None,
            mail.fetch,
            eid,
            "(BODY.PEEK[HEADER.FIELDS (To)])"
        )
        if st != "OK" or not hdr or not hdr[0][1]:
            continue
        raw = hdr[0][1].decode("utf-8", errors="ignore")
        m = re.search(r"^To:\s*(.+)$", raw, flags=re.MULTILINE)
        if m:
            addrs.update(addr for _, addr in getaddresses([m.group(1)]))

    # 4️⃣ Check each address for email- or phone-update messages
    unused, used = [], []
    for addr in sorted(addrs):
        # single-argument SEARCH with quoted criteria
        st1, d1 = await loop.run_in_executor(
            None,
            mail.search,
            None,
            f'(TO "{addr}" SUBJECT "your Uber account email was updated")'
        )
        st2, d2 = await loop.run_in_executor(
            None,
            mail.search,
            None,
            f'(TO "{addr}" SUBJECT "your Uber account phone number was updated")'
        )

        if (st1 == "OK" and d1 and d1[0]) or (st2 == "OK" and d2 and d2[0]):
            used.append(addr)
        else:
            unused.append(addr)

    # 5️⃣ Cleanup
    await loop.run_in_executor(None, mail.close)
    await loop.run_in_executor(None, mail.logout)

    # 6️⃣ Log counts & timing
    elapsed = time.time() - start_time
    logging.info(
        f"[usedchecker] scanned {len(promo_ids)} promos, checked {len(addrs)} accounts in {elapsed:.2f}s"
    )

    # 7️⃣ Send only the lists
    parts = []
    if unused:
        parts.append("**Unused accounts:**\n" + "\n".join(unused))
    if used:
        parts.append("**Used accounts:**\n" + "\n".join(used))
    
    output = "\n\n".join(parts) or "❌ No accounts found."
    
    if len(output) > 1900:
        fp = io.StringIO(output)
        await interaction.followup.send(
            file=discord.File(fp, filename="usedchecker_results.txt")
        )
    else:
        await interaction.followup.send(output)

    
if __name__ == '__main__':
    bot.run(os.getenv('DISCORD_BOT_TOKEN'))
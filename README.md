# Prin's Bot  

A Discord bot that scrapes your Gmail inbox for promo codes and one-time passwords (OTPs), returning them via slash commands.

Curated for ZR Eats method users, hosted locally. Written mostly by ChatGPT and DeepSeek.

<picture>
  <img alt="prin" src="https://i.imgur.com/r0IGEAc.png">
</picture>

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Slash Commands](#slash-commands)
  - [Examples](#examples)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Credential Management**: Securely store your Gmail address and app-specific IMAP password via `/setcreds`.
- **Promo Search** (`/searchpromo`): Search for a specific promo code across recent emails and list matching addresses (with expiry if enabled).
- **OTP Grabber** (`/grab`): Automatically find and return a 4-digit verification code sent to a forwarded address.
- **Preset Promo Lookup** (`/searchselect`): Quickly find all addresses that received the `WELCOME25B` promo in the past X days.
- **Used Checker** (`/usedchecker`): Identify which promo code accounts (default `WELCOME25B`) have subsequently been updated or used, optionally specifying a different promo and lookback period.
- **Credential Clearing** (`/clearcreds`): Remove your stored Gmail credentials.

## Architecture

- **Language**: Python (3.9+)
- **Discord Library**: `discord.py` v2.x with built-in `app_commands` (slash commands)
- **Email Access**: `imaplib` in background threads to avoid blocking the asyncio event loop
- **Storage**: SQLite database (`user_credentials.db`) for encrypted credentials
- **Encryption**: Fernet (AES-based) via the `cryptography` package

## Prerequisites

1. **Python** 3.9 or higher
2. **Discord Bot** with a valid **Bot Token** and **application commands** enabled
3. **Gmail Account** set up with:
   - **IMAP enabled** (Gmail settings → “Forwarding and POP/IMAP”)
   - **2-factor authentication** and a **16-character app-specific password**

## Installation

```bash
# Clone this repository
git clone https://github.com/bryanygan/promoscraper.git
cd promoscraper

# (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # on Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `.env` (or export environment variables) with:

```bash
# Your Discord bot token
export DISCORD_BOT_TOKEN="YOUR_DISCORD_TOKEN"

# Base64-encoded Fernet key for encrypting IMAP passwords
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
export ENCRYPTION_KEY="YOUR_FERNET_KEY"

# Optional: override IMAP server/port (defaults are Gmail)
export IMAP_SERVER="imap.gmail.com"
export IMAP_PORT=993
```

## Usage

### Slash Commands

| Command             | Description                                                                                         |
|---------------------|-----------------------------------------------------------------------------------------------------|
| `/setcreds`         | Store your Gmail address and app password securely                                                  |
| `/searchpromo`      | Search for any promo code: `/searchpromo <days_back> <code>`                                        |
| `/grab`             | Grab a 4-digit OTP sent to a forwarded address: `/grab <address>`                                   |
| `/searchselect`     | Find all addresses that received `WELCOME25B`: `/searchselect [days_back]`                          |
| `/usedchecker`      | Check which promo code accounts have been used or updated: `/usedchecker [days_back] [promo_code]`  |
| `/clearcreds`       | Clear your stored email and app password                                                            |

### Examples

```text
# Store credentials
/setcreds email:youremail@gmail.com app_password:ABCDEFGHIJKLMNOP

# Search for the code “SAVE20” in the last 5 days
/searchpromo days_back:5 search_code:SAVE20

# Grab OTP for a forwarded alias
/grab target_address:alias123@forwarder.com

# Find everyone who got WELCOME25B in the last 3 days
/searchselect days_back:3

# Check which WELCOME25B accounts have been used in the last 5 days
/usedchecker days_back:5

# Check which SAVE20 promo accounts have been used in the last 7 days
/usedchecker days_back:7 promo_code:SAVE20

# Clear your stored credentials
/clearcreds
```

## Security

- **Fernet Encryption**: All app-passwords are encrypted at rest in `user_credentials.db`
- **Ephemeral Responses**: Sensitive commands (`/setcreds`, `/grab`, `/clearcreds`) use ephemeral messages so only you see them

## Troubleshooting

- **Heartbeat Warnings**: Ensure all blocking IMAP calls are off-loaded via `run_in_executor`.
- **Slash Commands Not Showing**: Commands auto-sync globally; it may take up to an hour. For immediate testing, sync to a test guild via `await bot.tree.sync(guild=discord.Object(id=YOUR_GUILD_ID))`.
- **Authentication Errors**: Verify 2FA + app password combo, and that IMAP is enabled in Gmail.
- **Wrong OTP or No Matches**: Add logging around `get_email_body()` to inspect parsed content.

## License

This project is licensed under the **MIT License**.



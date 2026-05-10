import os
import re
import json
import socket
import asyncio
import ipaddress
import subprocess

import requests
import yt_dlp
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
    ConversationHandler,
)

# ──────────────────────────────
# Config
# ──────────────────────────────
load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")

DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

MAX_VIDEO_MB = 48

# ──────────────────────────────
# Branding
# ──────────────────────────────
BANNER = (
    "👁️ *VoidEye OSINT Bot*\n"
    "━━━━━━━━━━━━━━━━━━━━\n"
    "🛠️ Built by *Shen & KHONSHU*\n"
    "━━━━━━━━━━━━━━━━━━━━\n\n"
)

# ──────────────────────────────
# Helpers
# ──────────────────────────────
def dev_button():
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("👨‍💻 Developer", url="https://t.me/deweni2")]]
    )

def search_query(q: str) -> str:
    if q.startswith("http"):
        return q
    return f"ytsearch1:{q}"

def build_caption(info, user, is_audio=False):
    size = info.get("filesize") or info.get("filesize_approx") or 0
    size_mb = round(size / 1024 / 1024, 2)

    upload_date = info.get("upload_date")
    if upload_date and len(upload_date) == 8:
        upload_date = f"{upload_date[:4]}-{upload_date[4:6]}-{upload_date[6:]}"
    else:
        upload_date = "N/A"

    duration = info.get("duration")
    if duration:
        m, s = divmod(duration, 60)
        duration_str = f"{m}:{s:02d}"
    else:
        duration_str = "N/A"

    age_restricted = "Yes" if info.get("age_limit", 0) > 0 else "No"
    category = (info.get("categories") or ["N/A"])[0]
    emoji = "🎵" if is_audio else "🎬"

    return (
        f"{emoji} *Title:* {info.get('title','N/A')}\n"
        f"📺 *Channel:* {info.get('uploader','N/A')}\n"
        f"📂 *Category:* {category}\n"
        f"📅 *Upload Date:* {upload_date}\n"
        f"⏰ *Duration:* {duration_str}\n"
        f"👀 *Views:* {info.get('view_count','N/A')}\n"
        f"👍 *Likes:* {info.get('like_count','Hidden')}\n"
        f"💬 *Comments:* {info.get('comment_count','Hidden')}\n"
        f"📦 *File Size:* {size_mb} MB\n"
        f"⚖️ *License:* {info.get('license','Standard')}\n"
        f"🔞 *Age Restricted:* {age_restricted}\n\n"
        f"🙋 *Requested by:* {user.mention_markdown()}"
    )


# ══════════════════════════════════════════════════════════
#  OSINT HELPERS
# ══════════════════════════════════════════════════════════

# ── 1. Digital Footprint ──────────────────────────────────
SHERLOCK_SITES = {
    "GitHub":       "https://github.com/{}",
    "Twitter/X":    "https://twitter.com/{}",
    "Instagram":    "https://www.instagram.com/{}",
    "Reddit":       "https://www.reddit.com/user/{}",
    "TikTok":       "https://www.tiktok.com/@{}",
    "YouTube":      "https://www.youtube.com/@{}",
    "Pinterest":    "https://www.pinterest.com/{}",
    "Telegram":     "https://t.me/{}",
    "Twitch":       "https://www.twitch.tv/{}",
    "LinkedIn":     "https://www.linkedin.com/in/{}",
    "Medium":       "https://medium.com/@{}",
    "DevTo":        "https://dev.to/{}",
    "Patreon":      "https://www.patreon.com/{}",
    "SoundCloud":   "https://soundcloud.com/{}",
    "Spotify":      "https://open.spotify.com/user/{}",
    "Keybase":      "https://keybase.io/{}",
    "Hackernews":   "https://news.ycombinator.com/user?id={}",
    "GitLab":       "https://gitlab.com/{}",
    "Bitbucket":    "https://bitbucket.org/{}",
    "Steam":        "https://steamcommunity.com/id/{}",
    "Roblox":       "https://www.roblox.com/user.aspx?username={}",
    "Flickr":       "https://www.flickr.com/people/{}",
    "Vimeo":        "https://vimeo.com/{}",
    "VK":           "https://vk.com/{}",
}

async def check_username_sites(username: str) -> dict:
    """Check username across multiple sites concurrently."""
    found = {}
    headers = {"User-Agent": "Mozilla/5.0"}

    async def check(session_name, url):
        try:
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: requests.get(url, headers=headers, timeout=6, allow_redirects=True)
            )
            if resp.status_code == 200 and username.lower() in resp.url.lower():
                found[session_name] = url
        except Exception:
            pass

    tasks = [check(name, url.format(username)) for name, url in SHERLOCK_SITES.items()]
    await asyncio.gather(*tasks)
    return found


# ── 2. IP Intelligence ────────────────────────────────────
def get_ip_info(ip: str) -> dict:
    """Get geolocation + ISP + VPN/proxy/Tor status for an IP."""
    try:
        # Primary: ip-api.com (free, no key needed)
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query",
            timeout=8,
        )
        data = r.json()
        return data
    except Exception as e:
        return {"status": "fail", "message": str(e)}


def scan_common_ports(ip: str, ports=(21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080)) -> dict:
    """Quick TCP connect scan on common ports."""
    results = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        state = "open" if sock.connect_ex((ip, port)) == 0 else "closed"
        sock.close()
        results[port] = state
    return results


# ── 3. Domain Recon ──────────────────────────────────────
def domain_recon(domain: str) -> dict:
    """Whois + DNS + basic header fingerprinting."""
    result = {}

    # --- Whois via whois.iana.org REST API (no external lib needed) ---
    try:
        r = requests.get(f"https://www.whois.com/whois/{domain}", timeout=8,
                         headers={"User-Agent": "Mozilla/5.0"})
        # Scrape key lines from whois page
        whois_patterns = {
            "Registrar": r"Registrar:\s*(.+)",
            "Created":   r"Creation Date:\s*(.+)",
            "Expires":   r"Expiry Date:\s*(.+)",
            "Name Servers": r"Name Server:\s*(.+)",
        }
        whois_data = {}
        for key, pattern in whois_patterns.items():
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            if matches:
                whois_data[key] = matches[0].strip()
        result["whois"] = whois_data
    except Exception as e:
        result["whois"] = {"error": str(e)}

    # --- DNS Records ---
    dns_types = ["A", "MX", "NS", "TXT", "CNAME"]
    dns_results = {}
    for rtype in dns_types:
        try:
            cmd = ["nslookup", f"-type={rtype}", domain]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5).decode()
            lines = [l.strip() for l in out.splitlines() if domain.lower() in l.lower() and "=" in l]
            if lines:
                dns_results[rtype] = lines[:3]
        except Exception:
            pass
    result["dns"] = dns_results

    # --- Tech fingerprint via server headers ---
    try:
        url = f"https://{domain}" if not domain.startswith("http") else domain
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        headers = dict(r.headers)
        tech = {}
        if "X-Powered-By" in headers:
            tech["X-Powered-By"] = headers["X-Powered-By"]
        if "Server" in headers:
            tech["Server"] = headers["Server"]
        if "X-Generator" in headers:
            tech["X-Generator"] = headers["X-Generator"]
        # CMS hints from HTML
        body = r.text[:3000]
        if "wp-content" in body:
            tech["CMS"] = "WordPress"
        elif "Joomla" in body:
            tech["CMS"] = "Joomla"
        elif "Drupal" in body:
            tech["CMS"] = "Drupal"
        elif "shopify" in body.lower():
            tech["CMS"] = "Shopify"
        result["tech"] = tech
        result["status_code"] = r.status_code
    except Exception as e:
        result["tech"] = {"error": str(e)}

    return result


# ── 4. EXIF / Image Metadata ──────────────────────────────
def dms_to_decimal(dms, ref):
    """Convert GPS DMS tuple to decimal degrees."""
    try:
        d, m, s = [float(x) for x in dms]
        dec = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            dec = -dec
        return round(dec, 7)
    except Exception:
        return None

def extract_exif(image_path: str) -> dict:
    """Extract all EXIF + GPS data from an image."""
    try:
        img = Image.open(image_path)
        raw_exif = img._getexif()
        if not raw_exif:
            return {"error": "No EXIF data found in this image."}

        data = {}
        gps_raw = {}

        for tag_id, value in raw_exif.items():
            tag = TAGS.get(tag_id, str(tag_id))
            if tag == "GPSInfo":
                for gps_id, gps_val in value.items():
                    gps_tag = GPSTAGS.get(gps_id, str(gps_id))
                    gps_raw[gps_tag] = gps_val
            else:
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="ignore")
                    except Exception:
                        value = str(value)
                data[tag] = str(value)

        # Parse GPS
        if gps_raw:
            lat = dms_to_decimal(
                gps_raw.get("GPSLatitude", [0, 0, 0]),
                gps_raw.get("GPSLatitudeRef", "N"),
            )
            lon = dms_to_decimal(
                gps_raw.get("GPSLongitude", [0, 0, 0]),
                gps_raw.get("GPSLongitudeRef", "E"),
            )
            if lat and lon:
                data["GPS_Latitude"]  = lat
                data["GPS_Longitude"] = lon
                data["GPS_MapLink"]   = f"https://maps.google.com/?q={lat},{lon}"
            alt = gps_raw.get("GPSAltitude")
            if alt:
                data["GPS_Altitude"] = f"{round(float(alt), 2)} m"

        return data
    except Exception as e:
        return {"error": str(e)}


# ── 5. Breach / Leak Check ───────────────────────────────
def check_breach(email: str) -> dict:
    """Check email against HaveIBeenPwned API v3."""
    headers = {
        "User-Agent": "VoidEye-OSINT-Bot",
        "hibp-api-key": os.getenv("HIBP_API_KEY", ""),
    }
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return {"status": "breached", "breaches": r.json()}
        elif r.status_code == 404:
            return {"status": "clean"}
        elif r.status_code == 401:
            return {"status": "error", "message": "HIBP API key missing or invalid. Set HIBP_API_KEY in .env"}
        else:
            return {"status": "error", "message": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ══════════════════════════════════════════════════════════
#  ORIGINAL COMMANDS  (song / video)
# ══════════════════════════════════════════════════════════

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        BANNER +
        "📡 *OSINT Commands:*\n"
        "🔍 `/footprint <username>` – Social media presence\n"
        "🌐 `/ipinfo <ip>` – IP geolocation + ports\n"
        "🕸️ `/domain <domain>` – Whois + DNS + tech stack\n"
        "🖼️ `/exif` – Send image → extract EXIF/GPS\n"
        "🔓 `/breach <email>` – Data breach check\n\n"
        "🎵 *Media Commands:*\n"
        "🎵 `/song <name or url>` – Download song\n"
        "🎬 `/video <name or url>` – Download video\n\n"
        "Example:\n"
        "`/footprint johndoe`\n"
        "`/ipinfo 8.8.8.8`\n"
        "`/domain example.com`",
        parse_mode="Markdown",
        reply_markup=dev_button(),
    )


async def song(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ `/song <name or url>`", parse_mode="Markdown")
        return

    query = search_query(" ".join(context.args))
    ydl_opts = {
        "format": "bestaudio[ext=m4a]/bestaudio",
        "outtmpl": f"{DOWNLOAD_DIR}/%(title)s.%(ext)s",
        "noplaylist": True,
        "quiet": True,
    }
    service_msg = await update.message.reply_text("🎧 Downloading song...")
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(query, download=True)
            if "entries" in info:
                info = info["entries"][0]
            file_path = ydl.prepare_filename(info)

        caption = build_caption(info, update.message.from_user, is_audio=True)
        await update.message.reply_audio(
            audio=open(file_path, "rb"),
            caption=caption,
            parse_mode="Markdown",
            reply_markup=dev_button(),
        )
        os.remove(file_path)
    except Exception as e:
        await update.message.reply_text(f"❌ Error:\n`{e}`", parse_mode="Markdown")
    finally:
        try:
            await service_msg.delete()
        except Exception:
            pass


async def video(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ `/video <name or url>`", parse_mode="Markdown")
        return

    query = search_query(" ".join(context.args))
    ydl_opts = {
        "format": "best[ext=mp4][filesize_approx<50M]/best",
        "outtmpl": f"{DOWNLOAD_DIR}/%(title)s.%(ext)s",
        "merge_output_format": "mp4",
        "noplaylist": True,
        "quiet": True,
    }
    service_msg = await update.message.reply_text("🎬 Downloading video...")
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(query, download=True)
            if "entries" in info:
                info = info["entries"][0]
            file_path = ydl.prepare_filename(info)

        size_mb = os.path.getsize(file_path) / 1024 / 1024
        if size_mb > MAX_VIDEO_MB:
            os.remove(file_path)
            await update.message.reply_text(f"❌ Video too large ({round(size_mb,2)} MB)")
            return

        caption = build_caption(info, update.message.from_user)
        await update.message.reply_video(
            video=open(file_path, "rb"),
            caption=caption,
            parse_mode="Markdown",
            reply_markup=dev_button(),
        )
        os.remove(file_path)
    except Exception as e:
        await update.message.reply_text(f"❌ Error:\n`{e}`", parse_mode="Markdown")
    finally:
        try:
            await service_msg.delete()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
#  OSINT COMMANDS
# ══════════════════════════════════════════════════════════

# ── 1. /footprint ─────────────────────────────────────────
async def footprint(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❌ Usage: `/footprint <username>`", parse_mode="Markdown"
        )
        return

    username = context.args[0].strip().lstrip("@")
    msg = await update.message.reply_text(
        f"🔍 Scanning `{username}` across {len(SHERLOCK_SITES)} platforms...",
        parse_mode="Markdown",
    )

    found = await check_username_sites(username)

    if not found:
        text = (
            BANNER +
            f"👤 *Username:* `{username}`\n\n"
            "❌ No public profiles found on checked platforms."
        )
    else:
        lines = "\n".join(f"✅ [{name}]({url})" for name, url in found.items())
        text = (
            BANNER +
            f"👤 *Username:* `{username}`\n"
            f"📊 *Found on {len(found)}/{len(SHERLOCK_SITES)} platforms:*\n\n"
            + lines
        )

    await msg.edit_text(text, parse_mode="Markdown", disable_web_page_preview=True,
                        reply_markup=dev_button())


# ── 2. /ipinfo ────────────────────────────────────────────
async def ipinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: `/ipinfo <ip_address>`", parse_mode="Markdown")
        return

    ip = context.args[0].strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        await update.message.reply_text("❌ Invalid IP address format.", parse_mode="Markdown")
        return

    msg = await update.message.reply_text(f"🌐 Analyzing IP `{ip}`...", parse_mode="Markdown")

    info = get_ip_info(ip)
    ports = scan_common_ports(ip)

    open_ports  = [str(p) for p, s in ports.items() if s == "open"]
    closed_ports = [str(p) for p, s in ports.items() if s == "closed"]

    if info.get("status") == "success":
        proxy_status = "⚠️ Yes (VPN/Proxy/Hosting)" if (info.get("proxy") or info.get("hosting")) else "✅ No"
        text = (
            BANNER +
            f"🌐 *IP Intelligence Report*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🔢 *IP:* `{info.get('query','N/A')}`\n"
            f"🌍 *Country:* {info.get('country','N/A')}\n"
            f"🏙️ *Region:* {info.get('regionName','N/A')}\n"
            f"🏘️ *City:* {info.get('city','N/A')}\n"
            f"📮 *ZIP:* {info.get('zip','N/A')}\n"
            f"📍 *Lat/Lon:* {info.get('lat','?')}, {info.get('lon','?')}\n"
            f"🗺️ *Map:* [View Location](https://maps.google.com/?q={info.get('lat')},{info.get('lon')})\n"
            f"⏰ *Timezone:* {info.get('timezone','N/A')}\n"
            f"🏢 *ISP:* {info.get('isp','N/A')}\n"
            f"🏛️ *Org:* {info.get('org','N/A')}\n"
            f"📡 *ASN:* {info.get('as','N/A')}\n"
            f"🛡️ *VPN/Proxy:* {proxy_status}\n\n"
            f"🔓 *Open Ports:* `{', '.join(open_ports) if open_ports else 'None detected'}`\n"
            f"🔒 *Closed Ports:* `{', '.join(closed_ports[:5])}{'...' if len(closed_ports)>5 else ''}`"
        )
    else:
        text = (
            BANNER +
            f"❌ *IP Lookup Failed*\n"
            f"Reason: `{info.get('message','Unknown error')}`\n\n"
            f"🔓 *Open Ports:* `{', '.join(open_ports) if open_ports else 'None'}`"
        )

    await msg.edit_text(text, parse_mode="Markdown", disable_web_page_preview=True,
                        reply_markup=dev_button())


# ── 3. /domain ────────────────────────────────────────────
async def domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: `/domain <domain.com>`", parse_mode="Markdown")
        return

    dom = context.args[0].strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    msg = await update.message.reply_text(f"🕸️ Scanning `{dom}`...", parse_mode="Markdown")

    data = domain_recon(dom)

    # Whois
    whois = data.get("whois", {})
    whois_lines = "\n".join(f"  • *{k}:* `{v}`" for k, v in whois.items() if "error" not in k)
    if not whois_lines:
        whois_lines = "  _(No data)_"

    # DNS
    dns = data.get("dns", {})
    dns_lines = "\n".join(
        f"  • *{rtype}:* `{', '.join(vals)}`" for rtype, vals in dns.items()
    )
    if not dns_lines:
        dns_lines = "  _(No data)_"

    # Tech
    tech = data.get("tech", {})
    tech_lines = "\n".join(f"  • *{k}:* `{v}`" for k, v in tech.items() if "error" not in k)
    if not tech_lines:
        tech_lines = "  _(No data)_"

    text = (
        BANNER +
        f"🕸️ *Domain Reconnaissance*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *Domain:* `{dom}`\n"
        f"📶 *HTTP Status:* `{data.get('status_code','N/A')}`\n\n"
        f"📋 *Whois Info:*\n{whois_lines}\n\n"
        f"🗂️ *DNS Records:*\n{dns_lines}\n\n"
        f"⚙️ *Tech Stack:*\n{tech_lines}"
    )

    await msg.edit_text(text, parse_mode="Markdown", disable_web_page_preview=True,
                        reply_markup=dev_button())


# ── 4. /exif (ConversationHandler) ───────────────────────
WAITING_FOR_IMAGE = 1

async def exif_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🖼️ *EXIF Extractor*\n\n"
        "Now send me a photo (as a *file/document*, not compressed) "
        "and I'll extract all hidden metadata including GPS coordinates.",
        parse_mode="Markdown",
    )
    return WAITING_FOR_IMAGE


async def exif_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Accept photo or document
    if update.message.document:
        file_obj = update.message.document
    elif update.message.photo:
        file_obj = update.message.photo[-1]
    else:
        await update.message.reply_text("❌ Please send an image file.")
        return WAITING_FOR_IMAGE

    msg = await update.message.reply_text("🔍 Extracting EXIF data...")

    tg_file = await context.bot.get_file(file_obj.file_id)
    local_path = os.path.join(DOWNLOAD_DIR, f"exif_{file_obj.file_id}.jpg")
    await tg_file.download_to_drive(local_path)

    exif_data = extract_exif(local_path)

    try:
        os.remove(local_path)
    except Exception:
        pass

    if "error" in exif_data:
        await msg.edit_text(
            BANNER + f"❌ *EXIF Error:*\n`{exif_data['error']}`",
            parse_mode="Markdown",
        )
        return ConversationHandler.END

    # Priority fields to show first
    priority = ["GPS_Latitude","GPS_Longitude","GPS_MapLink","GPS_Altitude",
                "Make","Model","DateTime","DateTimeOriginal","Software",
                "ImageWidth","ImageLength","ExifImageWidth","ExifImageHeight"]

    lines = []
    for key in priority:
        if key in exif_data:
            val = exif_data.pop(key)
            if key == "GPS_MapLink":
                lines.append(f"🗺️ *Map:* [Open in Google Maps]({val})")
            else:
                lines.append(f"  • *{key}:* `{val}`")

    # Remaining fields (limit to 20)
    extra = list(exif_data.items())[:20]
    for k, v in extra:
        lines.append(f"  • *{k}:* `{str(v)[:80]}`")

    text = (
        BANNER +
        "🖼️ *EXIF Metadata Report*\n"
        "━━━━━━━━━━━━━━━━━━━━\n" +
        "\n".join(lines)
    )

    await msg.edit_text(text, parse_mode="Markdown", disable_web_page_preview=True,
                        reply_markup=dev_button())
    return ConversationHandler.END


async def exif_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ EXIF extraction cancelled.")
    return ConversationHandler.END


# ── 5. /breach ────────────────────────────────────────────
async def breach(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: `/breach <email@example.com>`", parse_mode="Markdown")
        return

    email = context.args[0].strip()
    if "@" not in email or "." not in email.split("@")[-1]:
        await update.message.reply_text("❌ Invalid email address.", parse_mode="Markdown")
        return

    msg = await update.message.reply_text(
        f"🔓 Checking `{email}` against known data breaches...", parse_mode="Markdown"
    )

    result = check_breach(email)

    if result["status"] == "clean":
        text = (
            BANNER +
            f"✅ *No Breaches Found!*\n\n"
            f"📧 *Email:* `{email}`\n"
            f"🛡️ This email was NOT found in any known data breach.\n\n"
            f"_Stay safe! Use strong, unique passwords._"
        )
    elif result["status"] == "breached":
        breaches = result["breaches"]
        breach_count = len(breaches)

        details = []
        for b in breaches[:8]:  # show max 8
            name  = b.get("Name", "Unknown")
            date  = b.get("BreachDate", "?")
            count = b.get("PwnCount", 0)
            types = ", ".join(b.get("DataClasses", [])[:4])
            details.append(f"  ⚠️ *{name}* ({date})\n     👥 {count:,} accounts | 📂 {types}")

        text = (
            BANNER +
            f"🚨 *BREACHED! Data Found in {breach_count} Leak(s)*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📧 *Email:* `{email}`\n\n"
            + "\n\n".join(details) +
            ("\n\n_...and more_" if breach_count > 8 else "") +
            "\n\n🔒 *Change your passwords immediately!*"
        )
    else:
        text = (
            BANNER +
            f"❌ *Breach Check Error*\n`{result.get('message','Unknown error')}`\n\n"
            "_Tip: Add your HIBP API key to .env as `HIBP_API_KEY=your_key`_"
        )

    await msg.edit_text(text, parse_mode="Markdown", reply_markup=dev_button())


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
def main():
    app = ApplicationBuilder().token(TOKEN).build()

    # Original handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("song",  song))
    app.add_handler(CommandHandler("video", video))

    # OSINT handlers
    app.add_handler(CommandHandler("footprint", footprint))
    app.add_handler(CommandHandler("ipinfo",    ipinfo))
    app.add_handler(CommandHandler("domain",    domain))
    app.add_handler(CommandHandler("breach",    breach))

    # EXIF conversation
    exif_handler = ConversationHandler(
        entry_points=[CommandHandler("exif", exif_start)],
        states={
            WAITING_FOR_IMAGE: [
                MessageHandler(filters.Document.IMAGE | filters.PHOTO, exif_receive),
                CommandHandler("cancel", exif_cancel),
            ]
        },
        fallbacks=[CommandHandler("cancel", exif_cancel)],
    )
    app.add_handler(exif_handler)

    print("🚀 VoidEye OSINT Bot running...")
    app.run_polling()


if __name__ == "__main__":
    main()

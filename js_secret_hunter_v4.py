#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════╗
║        JS Secret Hunter v4 — أداة الأمن السيبراني الاحترافية             ║
║    كاشف مفاتيح API والتوكنات — للاستخدام الأخلاقي المرخص فقط           ║
╠══════════════════════════════════════════════════════════════════════════╣
║  الجديد في v4:                                                            ║
║  ① AST Analysis      — تحليل شجري للكود يفهم بنيته الحقيقية             ║
║  ② Auto-Deobfuscation — فك Base64/Hex/charCode/ROT13 تلقائياً            ║
║  ③ Network Interception — اعتراض Headers الطلبات عبر Playwright          ║
║  ④ Contextual Validation — رفض نتائج المحاطة بكلمات placeholder/test    ║
║  ⑤ Hidden Assets Discovery — بحث عن .env/config.json/backup files       ║
║  ⑥ Enhanced UI — شريط تقدم دقيق، سجل أسطر الكود، لوحة إحصاءات         ║
║  + كل مميزات v3: Source Maps, Browser Storage, Subdomains,              ║
║    Notifications, Cloud Storage, Entropy Highlighting                    ║
╚══════════════════════════════════════════════════════════════════════════╝

pip install requests beautifulsoup4 jsbeautifier playwright
python -m playwright install chromium
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, requests, re, json, os, math, time, datetime, base64
import html as html_mod, binascii, struct
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3, subprocess, platform, queue

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── اختياريات ────────────────────────────────────────────────────
try:
    import jsbeautifier; HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

try:
    from playwright.sync_api import sync_playwright; HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# pyjsparser للـ AST — نستخدم تحليلاً بسيطاً إذا لم يكن متاحاً
try:
    import pyjsparser; HAS_AST = True
except ImportError:
    HAS_AST = False

# ══════════════════════════════════════════════════════════════════
#  BLACKLIST & PRIORITY
# ══════════════════════════════════════════════════════════════════
DOMAIN_BLACKLIST = [
    "googletagmanager.com","google-analytics.com","googleapis.com",
    "gstatic.com","doubleclick.net","googlesyndication.com",
    "facebook.net","fbcdn.net","connect.facebook.net",
    "youtube.com","ytimg.com","twitter.com","twimg.com",
    "cdn.jsdelivr.net","cdnjs.cloudflare.com","unpkg.com",
    "jquery.com","jqueryui.com","bootstrapcdn.com","fontawesome.com",
    "hotjar.com","intercom.io","zendesk.com","newrelic.com",
    "bugsnag.com","sentry.io","segment.com","mixpanel.com",
    "amplitude.com","cloudflare.com","akamai.net","akamaized.net",
    "wp-includes","wp-content/plugins","recaptcha","captcha",
    "linkedin.com","instagram.com","tiktok.com","snapchat.com",
]

HIGH_PRIORITY_KEYWORDS = [
    "config","env","setting","setup","app.","main.","init","secret",
    "key","auth","api","credential","token","private","db.","database",
    "connection","deploy","prod","production","backend","server",
]

# ══════════════════════════════════════════════════════════════════
#  HIDDEN ASSETS WORDLIST  (Feature ⑤)
# ══════════════════════════════════════════════════════════════════
HIDDEN_ASSETS = [
    # Environment / Config
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.backup", ".env.bak", ".env.old", ".env.example",
    "config.json", "config.js", "config.yaml", "config.yml",
    "config.php", "configuration.json", "app.config.json",
    "settings.json", "settings.py", "local_settings.py",
    "database.yml", "database.json", "db.json", "db.config.js",
    # Package / Lock files
    "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "composer.json", "composer.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    # Backup / Exposed files
    "package.json.bak", "config.json.bak", "backup.sql",
    "backup.zip", "database.sql", ".git/config",
    ".git/HEAD", "web.config", "app.yaml", "app.yml",
    # Kubernetes / Docker
    "docker-compose.yml", "docker-compose.yaml",
    "kubernetes.yml", ".dockerenv",
    # CI/CD secrets
    ".travis.yml", ".circleci/config.yml",
    "Jenkinsfile", ".github/workflows/deploy.yml",
    # Cloud
    "credentials.json", "service-account.json",
    "gcloud-key.json", "firebase.json", ".firebaserc",
    "serverless.yml", "terraform.tfvars",
    # Common leak paths
    "api-keys.txt", "secrets.txt", "passwords.txt",
    "keys.json", "tokens.json", "auth.json",
]

# ══════════════════════════════════════════════════════════════════
#  CONTEXTUAL REJECTION PATTERNS  (Feature ④)
# ══════════════════════════════════════════════════════════════════
# إذا كان السياق يحتوي على هذه → نخفض الأولوية أو نتجاهل
FALSE_POSITIVE_CONTEXT = [
    r"placeholder",r"example",r"sample",r"demo",r"fake",
    r"console\.log",r"console\.warn",r"console\.error",
    r"//\s*todo",r"//\s*fixme",r"//\s*test",r"//\s*mock",
    r"unittest",r"spec\.",r"describe\(",r"it\(",r"test\(",
    r"\.test\.",r"\.spec\.",r"__test__",
    r"documentation",r"readme",r"comment",
    r"your[_\-\s]?key",r"insert[_\-\s]?here",r"replace[_\-\s]?me",
]
FP_COMPILED = [re.compile(p, re.IGNORECASE) for p in FALSE_POSITIVE_CONTEXT]

# ══════════════════════════════════════════════════════════════════
#  SECRET PATTERNS
# ══════════════════════════════════════════════════════════════════
SECRET_PATTERNS = [
    # AWS
    {"name":"AWS Access Key ID",        "svc":"AWS",        "severity":"CRITICAL",
     "pattern":r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"},
    {"name":"AWS Secret Access Key",    "svc":"AWS",        "severity":"CRITICAL",
     "pattern":r"(?i)(?:aws[_\-\s]?secret|secret[_\-\s]?access[_\-\s]?key)"
               r"""['\"\s]*[:=]['\"\s]*([A-Za-z0-9/+=]{40})"""},
    {"name":"AWS S3 Bucket URL",        "svc":"AWS",        "severity":"HIGH",
     "pattern":r"https?://([a-z0-9\-\.]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"},
    {"name":"AWS ARN",                  "svc":"AWS",        "severity":"MEDIUM",
     "pattern":r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s'\"]{5,}"},
    # Google
    {"name":"Google API Key",           "svc":"Google",     "severity":"HIGH",
     "pattern":r"AIza[0-9A-Za-z\-_]{35}"},
    {"name":"Google OAuth Token",       "svc":"Google",     "severity":"HIGH",
     "pattern":r"ya29\.[0-9A-Za-z\-_]{50,}"},
    {"name":"Google Service Account",   "svc":"Google",     "severity":"CRITICAL",
     "pattern":r'"type"\s*:\s*"service_account"'},
    {"name":"GCS Bucket URL",           "svc":"GCS",        "severity":"HIGH",
     "pattern":r"https?://storage\.googleapis\.com/([a-z0-9\-_\.]+)"},
    # Azure
    {"name":"Azure Storage Conn.",      "svc":"Azure",      "severity":"CRITICAL",
     "pattern":r"DefaultEndpointsProtocol=https;AccountName=[^;]{3,50};AccountKey=[A-Za-z0-9+/=]{88}"},
    {"name":"Azure Blob URL",           "svc":"Azure",      "severity":"HIGH",
     "pattern":r"https?://([a-z0-9]+)\.blob\.core\.windows\.net/([a-z0-9\-]+)"},
    {"name":"Azure SAS Token",          "svc":"Azure",      "severity":"HIGH",
     "pattern":r"sv=20\d\d-\d\d-\d\d&s[a-z]=.{10,100}&sig=[A-Za-z0-9%]{30,}"},
    # GitHub
    {"name":"GitHub PAT (Classic)",     "svc":"GitHub",     "severity":"CRITICAL",
     "pattern":r"ghp_[0-9A-Za-z]{36}"},
    {"name":"GitHub Fine-grained PAT",  "svc":"GitHub",     "severity":"CRITICAL",
     "pattern":r"github_pat_[A-Za-z0-9_]{82}"},
    {"name":"GitHub App Token",         "svc":"GitHub",     "severity":"HIGH",
     "pattern":r"ghs_[0-9A-Za-z]{36}"},
    # Stripe
    {"name":"Stripe Secret Key (Live)", "svc":"Stripe",     "severity":"CRITICAL",
     "pattern":r"sk_live_[0-9a-zA-Z]{24,}"},
    {"name":"Stripe Restricted Key",    "svc":"Stripe",     "severity":"HIGH",
     "pattern":r"rk_live_[0-9a-zA-Z]{24,}"},
    {"name":"Stripe Publishable Live",  "svc":"Stripe",     "severity":"MEDIUM",
     "pattern":r"pk_live_[0-9a-zA-Z]{24,}"},
    {"name":"Stripe Test Secret",       "svc":"Stripe",     "severity":"LOW",
     "pattern":r"sk_test_[0-9a-zA-Z]{24,}"},
    # Slack
    {"name":"Slack Bot Token",          "svc":"Slack",      "severity":"HIGH",
     "pattern":r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}"},
    {"name":"Slack User Token",         "svc":"Slack",      "severity":"HIGH",
     "pattern":r"xoxp-[0-9A-Za-z\-]{50,}"},
    {"name":"Slack Webhook",            "svc":"Slack",      "severity":"MEDIUM",
     "pattern":r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{24,}"},
    # Twilio
    {"name":"Twilio Account SID",       "svc":"Twilio",     "severity":"HIGH",
     "pattern":r"AC[0-9a-fA-F]{32}"},
    {"name":"Twilio Auth Token",        "svc":"Twilio",     "severity":"CRITICAL",
     "pattern":r"(?i)twilio[^'\"\n]{0,30}['\"]([0-9a-f]{32})['\"]"},
    # Firebase
    {"name":"Firebase API Key",         "svc":"Firebase",   "severity":"HIGH",
     "pattern":r"(?i)(?:firebase|apiKey)[^'\"\n]{0,30}(AIza[0-9A-Za-z\-_]{35})"},
    {"name":"Firebase DB URL",          "svc":"Firebase",   "severity":"MEDIUM",
     "pattern":r"https://[a-z0-9\-]+\.firebaseio\.com"},
    # JWT
    {"name":"JWT Token",                "svc":"Auth",       "severity":"HIGH",
     "pattern":r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"},
    # OpenAI / AI
    {"name":"OpenAI API Key (Legacy)",  "svc":"OpenAI",     "severity":"CRITICAL",
     "pattern":r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"},
    {"name":"OpenAI API Key (New)",     "svc":"OpenAI",     "severity":"CRITICAL",
     "pattern":r"sk-proj-[A-Za-z0-9_\-]{50,}"},
    {"name":"Anthropic API Key",        "svc":"Anthropic",  "severity":"CRITICAL",
     "pattern":r"sk-ant-[A-Za-z0-9_\-]{90,}"},
    {"name":"HuggingFace Token",        "svc":"HuggingFace","severity":"HIGH",
     "pattern":r"hf_[A-Za-z0-9]{30,}"},
    # Database
    {"name":"MongoDB URI",              "svc":"Database",   "severity":"CRITICAL",
     "pattern":r"mongodb(?:\+srv)?://[^:'\"\s]{3,}:[^@'\"\s]{3,}@[^\s'\"]+"},
    {"name":"MySQL URI",                "svc":"Database",   "severity":"CRITICAL",
     "pattern":r"mysql://[^:'\"\s]{3,}:[^@'\"\s]{3,}@[^\s'\"]+"},
    {"name":"PostgreSQL URI",           "svc":"Database",   "severity":"CRITICAL",
     "pattern":r"postgres(?:ql)?://[^:'\"\s]{3,}:[^@'\"\s]{3,}@[^\s'\"]+"},
    {"name":"Redis URI",                "svc":"Database",   "severity":"HIGH",
     "pattern":r"redis://(?:[^:'\"\s]+:[^@'\"\s]+@)?[^\s'\"]+:\d{4,5}"},
    # Email
    {"name":"SendGrid API Key",         "svc":"SendGrid",   "severity":"HIGH",
     "pattern":r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"},
    {"name":"Mailgun API Key",          "svc":"Mailgun",    "severity":"HIGH",
     "pattern":r"key-[0-9a-zA-Z]{32}"},
    {"name":"Mailchimp API Key",        "svc":"Mailchimp",  "severity":"HIGH",
     "pattern":r"[0-9a-f]{32}-us\d{1,2}"},
    # Cloud / CDN
    {"name":"Cloudinary URL",           "svc":"Cloudinary", "severity":"MEDIUM",
     "pattern":r"cloudinary://[0-9]{10,}:[A-Za-z0-9_\-]{27}@[a-z0-9]+"},
    {"name":"Mapbox Token",             "svc":"Mapbox",     "severity":"MEDIUM",
     "pattern":r"pk\.eyJ1[A-Za-z0-9_\-\.]{40,}"},
    {"name":"Square Access Token",      "svc":"Square",     "severity":"CRITICAL",
     "pattern":r"EAAAE[A-Za-z0-9_\-]{60,}"},
    # Generic (يتطلب تنصيص + طول كافٍ)
    {"name":"Generic API Key",          "svc":"Generic",    "severity":"MEDIUM",
     "pattern":r"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]"},
    {"name":"Generic Secret Key",       "svc":"Generic",    "severity":"MEDIUM",
     "pattern":r"(?i)(?:secret[_\-]?key|client[_\-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]"},
    {"name":"Generic Access Token",     "svc":"Generic",    "severity":"MEDIUM",
     "pattern":r"(?i)(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,128})['\"]"},
    {"name":"Password (Non-empty)",     "svc":"Generic",    "severity":"HIGH",
     "pattern":r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{15,})['\"]"},
    {"name":"Private Key Block",        "svc":"Crypto",     "severity":"CRITICAL",
     "pattern":r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"},
    # Network
    {"name":"Internal IPv4",            "svc":"Network",    "severity":"LOW",
     "pattern":r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"},
]

NULL_VALUES = {
    "null","undefined","none","false","true","your_api_key","your_secret",
    "your_token","xxxxxxxxxxx","xxxxxxxxxxxxxxxx","0000000000000000",
    "insert_key_here","api_key_here","example","changeme","replace_me",
    "dummy","<api_key>","<secret>","<token>","xxx","","test","sample",
    "placeholder","todo","fixme","n/a","na","empty","string","value",
}

SEVERITY_ORDER  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
SEVERITY_COLORS = {
    "CRITICAL":"#FF2244","HIGH":"#FF8C00","MEDIUM":"#FFD700",
    "LOW":"#00BFFF","INFO":"#445566","GOLDEN":"#FFD700",
}
ENTROPY_GOLD = 4.5
ENTROPY_WARN = 3.5

# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════
def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def entropy_label(val: str) -> tuple:
    e = shannon_entropy(val)
    if e >= ENTROPY_GOLD: return f"🌟 {e:.2f} (مؤكد)", True
    if e >= ENTROPY_WARN: return f"⚡ {e:.2f}", False
    return f"{e:.2f}", False

# ══════════════════════════════════════════════════════════════════
#  DEOBFUSCATION ENGINE  (Feature ②)
# ══════════════════════════════════════════════════════════════════
class Deobfuscator:
    """فك تشفير الكود المبهم قبل الفحص"""

    # Base64 strings ≥ 20 chars
    B64_RE = re.compile(r"['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]")
    # Hex strings \x41\x42...
    HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
    # String.fromCharCode(72,101,108,...)
    CHARCODE_RE = re.compile(
        r"String\.fromCharCode\s*\(([0-9,\s]+)\)", re.IGNORECASE)
    # Unicode escapes \u0041\u0042
    UNICODE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
    # Hex literal 0x41 0x42 array
    HEX_LIT_RE = re.compile(r"\[(?:\s*0x[0-9a-fA-F]{2}\s*,\s*){3,}0x[0-9a-fA-F]{2}\s*\]")
    # eval(atob(...))
    ATOB_RE    = re.compile(r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]", re.IGNORECASE)
    # ROT13
    ROT13_RE   = re.compile(r"['\"]([A-Za-z]{16,})['\"]")

    def _rot13(self, s: str) -> str:
        return s.translate(
            str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))

    def _safe_b64(self, s: str) -> str | None:
        try:
            pad = s + "=" * (-len(s) % 4)
            dec = base64.b64decode(pad).decode("utf-8", errors="replace")
            if any(c < " " and c not in "\n\r\t" for c in dec):
                return None
            return dec
        except Exception:
            return None

    def deobfuscate(self, code: str, log_cb=None) -> str:
        """يُرجع الكود مع إضافة السلاسل المفكوكة كتعليقات"""
        extra = []

        # 1. atob() — الأعلى أولوية
        for m in self.ATOB_RE.finditer(code):
            dec = self._safe_b64(m.group(1))
            if dec and len(dec) >= 8:
                extra.append(f'/* DEOB:atob => {dec[:300]} */')

        # 2. Base64 strings
        for m in self.B64_RE.finditer(code):
            val = m.group(1)
            if len(val) % 4 == 0 or len(val) % 4 == 3:
                dec = self._safe_b64(val)
                if dec and shannon_entropy(dec) > 2.5 and len(dec) >= 10:
                    extra.append(f'/* DEOB:b64 => {dec[:300]} */')

        # 3. String.fromCharCode
        for m in self.CHARCODE_RE.finditer(code):
            try:
                nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
                s = "".join(chr(n) for n in nums if 0 < n < 0x110000)
                if len(s) >= 8:
                    extra.append(f'/* DEOB:charCode => {s[:300]} */')
            except Exception:
                pass

        # 4. Hex escapes \x41\x42...
        for m in self.HEX_ESC_RE.finditer(code):
            try:
                s = bytes.fromhex(
                    re.sub(r"\\x", "", m.group(0))
                ).decode("utf-8", errors="replace")
                if len(s) >= 4:
                    extra.append(f'/* DEOB:hexesc => {s[:300]} */')
            except Exception:
                pass

        # 5. Unicode escapes
        for m in self.UNICODE_RE.finditer(code):
            try:
                s = m.group(0).encode().decode("unicode_escape")
                if len(s) >= 4:
                    extra.append(f'/* DEOB:unicode => {s[:300]} */')
            except Exception:
                pass

        # 6. Hex literal array
        for m in self.HEX_LIT_RE.finditer(code):
            try:
                nums = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(0))]
                s = bytes(nums).decode("utf-8", errors="replace")
                if len(s) >= 4:
                    extra.append(f'/* DEOB:hexarr => {s[:300]} */')
            except Exception:
                pass

        if extra:
            if log_cb:
                log_cb("INFO", f"   🔓 Deobfuscation: {len(extra)} سلسلة مفككة")
            return code + "\n" + "\n".join(extra)
        return code

DEOBFUSCATOR = Deobfuscator()

# ══════════════════════════════════════════════════════════════════
#  AST ANALYSIS ENGINE  (Feature ①)
# ══════════════════════════════════════════════════════════════════
class ASTAnalyzer:
    """
    تحليل شجري للكود JS — يستخدم pyjsparser إذا توفر،
    وإلا يستخدم تحليلاً مبسطاً قائماً على الـ Regex لاستخراج
    تعيينات المتغيرات والكشف عن دمج السلاسل النصية.
    """

    # كلمات تدل على مفاتيح (variable names)
    KEY_VAR_NAMES = re.compile(
        r"(?i)\b(?:api[_\-]?key|secret|token|password|credential|"
        r"auth|access[_\-]?key|private[_\-]?key|client[_\-]?secret)\b"
    )

    # تعيين متغير: var/let/const name = "value"
    VAR_ASSIGN_RE = re.compile(
        r"(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
        r"(?:(['\"])([^'\"]{8,})\2)",
        re.MULTILINE
    )

    # دمج سلاسل: "part1" + "part2" + ...
    STR_CONCAT_RE = re.compile(
        r"(?:['\"][A-Za-z0-9+/=_\-]{4,}['\"]"
        r"(?:\s*\+\s*['\"][A-Za-z0-9+/=_\-]{4,}['\"]){1,10})"
    )

    # object property: { key: "value" }
    OBJ_PROP_RE = re.compile(
        r"""(?i)(?:api[_\-]?key|secret|token|password|auth|credential|"""
        r"""private|access)['\"]?\s*:\s*(?:['\"])([A-Za-z0-9_\-\.+/=]{12,})['\"]""",
        re.MULTILINE
    )

    def analyze(self, code: str, source: str, log_cb=None) -> list:
        """يُرجع قائمة نتائج إضافية من التحليل الشجري"""
        findings = []

        if HAS_AST:
            findings.extend(self._ast_parse(code, source, log_cb))
        else:
            findings.extend(self._regex_ast(code, source))

        return findings

    def _ast_parse(self, code: str, source: str, log_cb) -> list:
        """تحليل باستخدام pyjsparser"""
        findings = []
        try:
            tree = pyjsparser.parse(code)
            self._walk(tree, findings, source)
            if log_cb:
                log_cb("INFO", f"   🌳 AST: {len(findings)} نتيجة من pyjsparser")
        except Exception:
            # fallback
            findings.extend(self._regex_ast(code, source))
        return findings

    def _walk(self, node, findings: list, source: str):
        if not isinstance(node, dict): return
        ntype = node.get("type","")

        # VariableDeclarator: let apiKey = "..."
        if ntype == "VariableDeclarator":
            name_node = node.get("id",{})
            init_node = node.get("init") or {}
            name = name_node.get("name","")
            if self.KEY_VAR_NAMES.search(name):
                val = self._extract_str(init_node)
                if val and len(val) >= 12 and val.lower() not in NULL_VALUES:
                    elabel, ig = entropy_label(val)
                    findings.append({
                        "name":      f"AST: Variable '{name}'",
                        "svc":       "AST",
                        "severity":  "HIGH" if ig else "MEDIUM",
                        "value":     val[:150],
                        "source":    source,
                        "context":   f"var {name} = \"{val[:60]}\"",
                        "entropy":   elabel,
                        "is_golden": ig,
                        "validation":"—",
                        "ast_source":True,
                    })

        # Property: { apiKey: "..." }
        elif ntype == "Property":
            key_node = node.get("key",{})
            val_node = node.get("value",{})
            key_name = key_node.get("name","") or key_node.get("value","")
            if self.KEY_VAR_NAMES.search(str(key_name)):
                val = self._extract_str(val_node)
                if val and len(val) >= 12 and val.lower() not in NULL_VALUES:
                    elabel, ig = entropy_label(val)
                    findings.append({
                        "name":      f"AST: Property '{key_name}'",
                        "svc":       "AST",
                        "severity":  "HIGH" if ig else "MEDIUM",
                        "value":     val[:150],
                        "source":    source,
                        "context":   f"{{{key_name}: \"{val[:60]}\"}}",
                        "entropy":   elabel,
                        "is_golden": ig,
                        "validation":"—",
                        "ast_source":True,
                    })

        # String concatenation binary expression
        elif ntype == "BinaryExpression" and node.get("operator") == "+":
            combined = self._concat_str(node)
            if combined and len(combined) >= 20:
                ent = shannon_entropy(combined)
                if ent >= ENTROPY_WARN:
                    elabel, ig = entropy_label(combined)
                    findings.append({
                        "name":      "AST: Concatenated String (High Entropy)",
                        "svc":       "AST",
                        "severity":  "MEDIUM",
                        "value":     combined[:150],
                        "source":    source,
                        "context":   "String concatenation detected",
                        "entropy":   elabel,
                        "is_golden": ig,
                        "validation":"—",
                        "ast_source":True,
                    })

        # recurse
        for v in node.values():
            if isinstance(v, dict):
                self._walk(v, findings, source)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        self._walk(item, findings, source)

    def _extract_str(self, node: dict) -> str | None:
        if not node: return None
        if node.get("type") == "Literal":
            v = node.get("value","")
            return str(v) if isinstance(v, str) else None
        if node.get("type") == "BinaryExpression":
            return self._concat_str(node)
        return None

    def _concat_str(self, node: dict) -> str | None:
        if node.get("type") == "Literal":
            return str(node.get("value",""))
        if node.get("type") == "BinaryExpression" and node.get("operator") == "+":
            l = self._concat_str(node.get("left",{}))
            r = self._concat_str(node.get("right",{}))
            if l is not None and r is not None:
                return l + r
        return None

    def _regex_ast(self, code: str, source: str) -> list:
        """تحليل مبسط بالـ Regex يحاكي الـ AST"""
        findings = []

        # متغيرات بأسماء حساسة
        for m in self.VAR_ASSIGN_RE.finditer(code):
            var_name, _, val = m.group(1), m.group(2), m.group(3)
            if self.KEY_VAR_NAMES.search(var_name) and val.lower() not in NULL_VALUES:
                if len(val) >= 12 and len(set(val)) >= 4:
                    elabel, ig = entropy_label(val)
                    findings.append({
                        "name":      f"AST-Regex: Variable '{var_name}'",
                        "svc":       "AST",
                        "severity":  "HIGH" if ig else "MEDIUM",
                        "value":     val[:150],
                        "source":    source,
                        "context":   m.group(0)[:120],
                        "entropy":   elabel,
                        "is_golden": ig,
                        "validation":"—",
                        "ast_source":True,
                    })

        # Object properties
        for m in self.OBJ_PROP_RE.finditer(code):
            val = m.group(1)
            if val.lower() not in NULL_VALUES and len(val) >= 12:
                elabel, ig = entropy_label(val)
                findings.append({
                    "name":      "AST-Regex: Object Property",
                    "svc":       "AST",
                    "severity":  "MEDIUM",
                    "value":     val[:150],
                    "source":    source,
                    "context":   m.group(0)[:120],
                    "entropy":   elabel,
                    "is_golden": ig,
                    "validation":"—",
                    "ast_source":True,
                })

        # String concatenation
        for m in self.STR_CONCAT_RE.finditer(code):
            parts = re.findall(r"['\"]([A-Za-z0-9+/=_\-]{4,})['\"]", m.group(0))
            combined = "".join(parts)
            if len(combined) >= 20 and shannon_entropy(combined) >= ENTROPY_WARN:
                elabel, ig = entropy_label(combined)
                findings.append({
                    "name":      "AST-Regex: Concatenated String",
                    "svc":       "AST",
                    "severity":  "MEDIUM",
                    "value":     combined[:150],
                    "source":    source,
                    "context":   m.group(0)[:120],
                    "entropy":   elabel,
                    "is_golden": ig,
                    "validation":"—",
                    "ast_source":True,
                })

        return findings

AST_ANALYZER = ASTAnalyzer()

# ══════════════════════════════════════════════════════════════════
#  CONTEXTUAL VALIDATOR  (Feature ④)
# ══════════════════════════════════════════════════════════════════
def contextual_filter(val: str, context: str) -> str:
    """
    يُرجع: "keep" | "downgrade" | "reject"
    """
    ctx_lower = context.lower()
    val_lower = val.lower()

    # رفض مباشر إذا كانت القيمة نفسها مشبوهة
    if val_lower in NULL_VALUES:
        return "reject"

    # رفض إذا كان السياق يحتوي إشارات false-positive
    for pat in FP_COMPILED:
        if pat.search(ctx_lower):
            return "downgrade"

    # رفض إذا كانت القيمة مجرد أحرف متكررة
    if len(set(val)) < 4:
        return "reject"

    # رفض أرقام بحتة
    if re.fullmatch(r"\d+", val):
        return "reject"

    # خفض إذا كانت القيمة قصيرة جداً لنوعها
    if len(val) < 10:
        return "downgrade"

    return "keep"

# ══════════════════════════════════════════════════════════════════
#  NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════
def desktop_notify(title: str, msg: str):
    try:
        sys_name = platform.system()
        if sys_name == "Windows":
            ps = (f"Add-Type -AssemblyName System.Windows.Forms;"
                  f"$n=New-Object System.Windows.Forms.NotifyIcon;"
                  f"$n.Icon=[System.Drawing.SystemIcons]::Warning;"
                  f"$n.Visible=$true;"
                  f"$n.ShowBalloonTip(8000,'{title}','{msg}',"
                  f"[System.Windows.Forms.ToolTipIcon]::Warning);"
                  f"Start-Sleep -s 9; $n.Dispose()")
            subprocess.Popen(["powershell","-WindowStyle","Hidden","-Command",ps],
                             creationflags=0x08000000)
        elif sys_name == "Darwin":
            subprocess.Popen(["osascript","-e",
                              f'display notification "{msg}" with title "{title}"'])
        else:
            subprocess.Popen(["notify-send", title, msg])
    except Exception:
        pass

def telegram_notify(token: str, chat_id: str, msg: str) -> bool:
    if not token or not chat_id: return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id":chat_id,"text":msg,"parse_mode":"HTML"},
            timeout=8)
        return r.ok
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════
#  LIVE VALIDATION
# ══════════════════════════════════════════════════════════════════
def validate_token(finding: dict) -> str:
    name = finding["name"]
    val  = finding["value"].rstrip("…")
    try:
        if "GitHub" in name:
            r = requests.get("https://api.github.com/user",
                headers={"Authorization":f"token {val}"},timeout=7)
            if r.status_code==200: return f"✅ صالح — {r.json().get('login','?')}"
            return f"❌ ({r.status_code})"
        elif "Stripe Secret" in name:
            r = requests.get("https://api.stripe.com/v1/account",auth=(val,""),timeout=7)
            if r.status_code==200: return f"✅ صالح — {r.json().get('id','?')}"
            return f"❌ ({r.status_code})"
        elif "HuggingFace" in name:
            r = requests.get("https://huggingface.co/api/whoami",
                headers={"Authorization":f"Bearer {val}"},timeout=7)
            if r.status_code==200: return f"✅ صالح — {r.json().get('name','?')}"
            return f"❌ ({r.status_code})"
        elif "Slack Bot" in name or "Slack User" in name:
            r = requests.post("https://slack.com/api/auth.test",
                headers={"Authorization":f"Bearer {val}"},timeout=7)
            d = r.json() if r.ok else {}
            if d.get("ok"): return f"✅ {d.get('team','?')}/{d.get('user','?')}"
            return f"❌ {d.get('error','')}"
        elif "Slack Webhook" in name:
            r = requests.post(val,json={"text":"ping"},timeout=7)
            return "✅ Webhook يعمل" if r.status_code==200 else f"❌ ({r.status_code})"
        elif "SendGrid" in name:
            r = requests.get("https://api.sendgrid.com/v3/user/profile",
                headers={"Authorization":f"Bearer {val}"},timeout=7)
            if r.status_code==200: return f"✅ {r.json().get('email','?')}"
            return f"❌ ({r.status_code})"
        elif "OpenAI" in name:
            r = requests.get("https://api.openai.com/v1/models",
                headers={"Authorization":f"Bearer {val}"},timeout=7)
            return "✅ OpenAI يعمل" if r.status_code==200 else f"❌ ({r.status_code})"
        elif "Google API Key" in name:
            test = f"https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={val}"
            r = requests.get(test,timeout=7)
            if r.status_code==200 and r.headers.get("content-type","").startswith("image"):
                return "✅ Google Maps يعمل"
            return "❌ مرفوض" if "REQUEST_DENIED" in r.text else f"⚠️ ({r.status_code})"
        elif "AWS S3" in name:
            bucket = re.search(r"https?://([^.]+)\.", val)
            if bucket:
                r = requests.get(f"https://{bucket.group(1)}.s3.amazonaws.com/",timeout=7)
                if r.status_code==200: return "🚨 OPEN BUCKET — مفتوح!"
                if r.status_code==403: return "🔒 موجود لكن محمي"
        elif "Azure Blob" in name:
            r = requests.get(val+"?restype=container&comp=list",timeout=7)
            if r.status_code==200: return "🚨 OPEN CONTAINER!"
            if r.status_code==403: return "🔒 محمي"
    except Exception as e:
        return f"⚠️ {str(e)[:50]}"
    return "—"

# ══════════════════════════════════════════════════════════════════
#  SCANNER  (v4)
# ══════════════════════════════════════════════════════════════════
class Scanner:
    def __init__(self, log_cb, progress_cb, status_cb=None):
        self.log       = log_cb
        self.prog      = progress_cb
        self.status    = status_cb or (lambda s: None)   # شريط الحالة
        self.stop_flag = False
        self.results   = []
        self.session   = requests.Session()
        self.session.headers.update({
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/124.0.0.0 Safari/537.36"
        })

    # ── Phase 1: Crawl ───────────────────────────────────────────
    def crawl(self, target_url, timeout, recursive_depth=1):
        self.log("INFO", f"[1/6] 🕷️  Crawling: {target_url}")
        js_urls, inlines, map_urls = [], [], []
        visited = set()

        def _crawl(url, depth):
            if url in visited or depth < 0 or self.stop_flag: return
            visited.add(url)
            try:
                r = self.session.get(url, timeout=timeout, verify=False)
                r.raise_for_status()
                soup  = BeautifulSoup(r.text, "html.parser")
                thost = urlparse(target_url).netloc
                for tag in soup.find_all("script"):
                    src = tag.get("src","").strip()
                    if src:
                        full = urljoin(url, src)
                        if full not in js_urls: js_urls.append(full)
                        mh = f"{full}.map"
                        if mh not in map_urls: map_urls.append(mh)
                    elif tag.string and tag.string.strip():
                        inlines.append(tag.string.strip())
                        sm = re.search(r"//# sourceMappingURL=([^\s]+)", tag.string)
                        if sm:
                            mu = urljoin(url, sm.group(1))
                            if mu not in map_urls: map_urls.append(mu)
                if depth > 0:
                    for a in soup.find_all("a", href=True):
                        href = urljoin(url, a["href"])
                        if urlparse(href).netloc == thost and href not in visited:
                            _crawl(href, depth-1)
            except Exception as e:
                self.log("INFO", f"   ⚠️  {url}: {e}")

        _crawl(target_url, recursive_depth)

        priority, normal, skipped = [], [], []
        thost = urlparse(target_url).netloc
        for url in js_urls:
            p = urlparse(url); h = p.netloc; path = p.path.lower()
            if any(b in h or b in path for b in DOMAIN_BLACKLIST):
                skipped.append(url); continue
            (priority if (thost in h or h in thost or
                          any(k in path for k in HIGH_PRIORITY_KEYWORDS))
             else normal).append(url)

        ordered = priority + normal
        self.log("INFO",
            f"   JS: {len(ordered)} (أولوية:{len(priority)} | عادي:{len(normal)} | "
            f"مستبعد:{len(skipped)}) | inline:{len(inlines)} | maps:{len(map_urls)}")
        return ordered, inlines, map_urls

    # ── Phase 2: Fetch ───────────────────────────────────────────
    def fetch_all(self, urls, timeout, workers):
        if not urls: return {}
        self.log("INFO", f"   ⬇️  تحميل {len(urls)} ملف (workers={workers})")
        out = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fmap = {ex.submit(self._fetch_one, u, timeout): u for u in urls}
            for fut in as_completed(fmap):
                if self.stop_flag: break
                out[fmap[fut]] = fut.result()
        return out

    def _fetch_one(self, url, timeout):
        try:
            r = self.session.get(url, timeout=timeout, verify=False)
            r.raise_for_status()
            return r.text
        except Exception as e:
            self.log("INFO", f"   ⚠️  {url.split('/')[-1][:35]}: {e}")
            return ""

    # ── Hidden Assets Discovery  (Feature ⑤) ────────────────────
    def discover_hidden_assets(self, target_url, timeout):
        self.log("INFO", "[★] 📁 Hidden Assets Discovery…")
        base = target_url.rstrip("/")
        found_assets = {}
        interesting = []

        def _probe(path):
            url = f"{base}/{path.lstrip('/')}"
            try:
                r = self.session.get(url, timeout=timeout//2, verify=False,
                                     allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    return url, r.text
            except Exception:
                pass
            return url, None

        with ThreadPoolExecutor(max_workers=15) as ex:
            fmap = {ex.submit(_probe, path): path for path in HIDDEN_ASSETS}
            for fut in as_completed(fmap):
                if self.stop_flag: break
                url, content = fut.result()
                if content:
                    fname = fmap[fut]
                    interesting.append((url, content, fname))
                    self.log("CRITICAL",
                        f"   🚨 وُجد: {fname} ({len(content)} bytes)")

        self.log("INFO",
            f"   ✅ Hidden Assets: فحص {len(HIDDEN_ASSETS)} ملف → {len(interesting)} موجود")
        return interesting

    # ── Network Interception (Playwright)  (Feature ③) ──────────
    def intercept_network(self, target_url, timeout):
        if not HAS_PLAYWRIGHT:
            return []
        self.log("INFO", "[★] 🌐 Network Interception + Browser Storage…")
        findings = []
        intercepted_headers = []

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context()
                page    = context.new_page()

                # اعتراض الطلبات
                def on_request(req):
                    hdrs = req.headers
                    for hname, hval in hdrs.items():
                        hname_l = hname.lower()
                        if hname_l in ("authorization","x-api-key","x-auth-token",
                                       "x-access-token","x-secret","api-key"):
                            if len(hval) > 10 and hval.lower() not in NULL_VALUES:
                                intercepted_headers.append({
                                    "header": hname,
                                    "value":  hval[:200],
                                    "url":    req.url[:120],
                                })

                page.on("request", on_request)

                try:
                    page.goto(target_url, timeout=timeout*1000,
                              wait_until="networkidle")
                except Exception:
                    pass

                # انتظار إضافي للطلبات الديناميكية
                time.sleep(3)

                # localStorage / sessionStorage
                for store_name, js_code in [
                    ("localStorage",
                     "()=>{let d={};for(let i=0;i<localStorage.length;i++){let k=localStorage.key(i);d[k]=localStorage.getItem(k);}return d;}"),
                    ("sessionStorage",
                     "()=>{let d={};for(let i=0;i<sessionStorage.length;i++){let k=sessionStorage.key(i);d[k]=sessionStorage.getItem(k);}return d;}")
                ]:
                    try:
                        store = page.evaluate(f"({js_code})()")
                        for k, v in (store or {}).items():
                            if not v or len(v) < 8: continue
                            found = self.scan_content(f'{k}="{v}"',
                                                      f"[Browser:{store_name}]")
                            findings.extend(found)
                            e = shannon_entropy(v)
                            if e >= ENTROPY_GOLD and len(v) >= 16:
                                el, ig = entropy_label(v)
                                findings.append({
                                    "name":f"High-Entropy {store_name}: {k}",
                                    "svc":"BrowserStorage","severity":"HIGH",
                                    "value":v[:150],"source":f"[Browser:{store_name}]",
                                    "context":f"key={k}","entropy":el,
                                    "is_golden":ig,"validation":"—",
                                })
                    except Exception:
                        pass

                # Cookies
                for ck in context.cookies():
                    v = ck.get("value","")
                    if len(v) >= 16 and shannon_entropy(v) >= ENTROPY_WARN:
                        el, ig = entropy_label(v)
                        findings.append({
                            "name":f"Sensitive Cookie: {ck.get('name','')}",
                            "svc":"Cookie","severity":"MEDIUM",
                            "value":v[:150],"source":"[Browser:Cookie]",
                            "context":f"domain={ck.get('domain','')}",
                            "entropy":el,"is_golden":ig,"validation":"—",
                        })

                browser.close()

            # معالجة الـ Headers المعترضة
            for h in intercepted_headers:
                el, ig = entropy_label(h["value"])
                dec = f"[Header: {h['header']}]"
                self.log("HIGH",
                    f"   🎯 Header مشبوه: {h['header']} = {h['value'][:60]}")
                findings.append({
                    "name":      f"Network Header: {h['header']}",
                    "svc":       "NetworkInterception",
                    "severity":  "CRITICAL",
                    "value":     h["value"],
                    "source":    f"[Network] {h['url']}",
                    "context":   f"Intercepted from request to {h['url']}",
                    "entropy":   el,
                    "is_golden": ig,
                    "validation":"—",
                })

            self.log("INFO",
                f"   ✅ Network: {len(intercepted_headers)} header مشبوه + "
                f"{len(findings)} نتيجة storage")
        except Exception as e:
            self.log("INFO", f"   ⚠️  Playwright: {e}")

        return findings

    # ── Source Maps ──────────────────────────────────────────────
    def extract_from_sourcemap(self, map_content, map_url):
        out = []
        try:
            data = json.loads(map_content)
            for i, src in enumerate(data.get("sourcesContent") or []):
                if src and len(src) > 50:
                    label = (data.get("sources",[]) or [None])[i] or f"src#{i}"
                    out.append((src, f"[MAP] {label}"))
        except Exception as e:
            self.log("INFO", f"   ⚠️  Map parse error: {e}")
        return out

    # ── Scan Content (Regex + Deobfuscation + AST + ContextFilter) ─
    def beautify(self, code):
        if not HAS_BEAUTIFIER or len(code) > 3_000_000: return code
        try:
            opts = jsbeautifier.default_options()
            opts.unescape_strings = True; opts.wrap_line_length = 0
            return jsbeautifier.beautify(code, opts)
        except Exception:
            return code

    def scan_content(self, content: str, source: str) -> list:
        # Step 1: Beautify
        code = self.beautify(content)

        # Step 2: Deobfuscate
        code = DEOBFUSCATOR.deobfuscate(code, self.log)

        # Step 3: Regex patterns
        found = []
        lines = code.split("\n")
        total_lines = len(lines)

        for pat in SECRET_PATTERNS:
            try:
                matches = re.findall(pat["pattern"], code, re.MULTILINE)
            except re.error:
                continue
            for m in matches:
                if self.stop_flag: break
                val = (m if isinstance(m,str) else m[0] if m else "").strip().strip("\"'")
                if not val or len(val) < 8 or len(set(val)) < 3 or val.isdigit():
                    continue
                ent = shannon_entropy(val)
                if pat["svc"] == "Generic" and ent < 3.0: continue

                idx = code.find(val)
                ctx = ""
                if idx != -1:
                    s = max(0, idx-50); e = min(len(code), idx+len(val)+50)
                    ctx = code[s:e].replace("\n"," ").replace("\t"," ").strip()

                # ④ Contextual filter
                decision = contextual_filter(val, ctx)
                if decision == "reject":
                    continue

                elabel, ig = entropy_label(val)
                sev = pat["severity"]
                if decision == "downgrade" and sev in ("CRITICAL","HIGH"):
                    sev = {"CRITICAL":"HIGH","HIGH":"MEDIUM"}[sev]

                found.append({
                    "name":      pat["name"],
                    "svc":       pat["svc"],
                    "severity":  sev,
                    "value":     val[:150]+("…" if len(val)>150 else ""),
                    "source":    source,
                    "context":   ctx,
                    "entropy":   elabel,
                    "is_golden": ig,
                    "validation":"—",
                    "lines":     total_lines,
                })

        # Step 4: AST Analysis
        if not source.startswith("[Browser"):
            ast_found = AST_ANALYZER.analyze(code, source, self.log)
            # تجنب تكرار القيم الموجودة بالفعل
            existing_vals = {f["value"][:40].lower() for f in found}
            for af in ast_found:
                if af["value"][:40].lower() not in existing_vals:
                    decision = contextual_filter(af["value"], af.get("context",""))
                    if decision != "reject":
                        if decision == "downgrade" and af["severity"] == "HIGH":
                            af["severity"] = "MEDIUM"
                        found.append(af)

        return found

    # ── Subdomain scan ───────────────────────────────────────────
    def scan_subdomains(self, findings, timeout, workers):
        self.log("INFO", "[★] 🌍 فحص النطاقات الفرعية…")
        extra = set()
        url_re = re.compile(r"https?://[^\s'\"<>]{10,}")
        for f in findings:
            for u in url_re.findall(f.get("context","")+f.get("value","")):
                extra.add(u)
        if not extra:
            self.log("INFO","   ℹ️  لا نطاقات فرعية"); return []
        self.log("INFO", f"   🔎 {len(extra)} رابط إضافي")
        new = []
        for url, code in self.fetch_all(list(extra)[:20], timeout, workers).items():
            if self.stop_flag: break
            if code: new.extend(self.scan_content(code, f"[Sub] {url}"))
        self.log("INFO", f"   ✅ subdomains: {len(new)} نتيجة جديدة")
        return new

    # ── Validate ─────────────────────────────────────────────────
    def validate_all(self, findings):
        for f in findings:
            if self.stop_flag: break
            if f["severity"] in ("CRITICAL","HIGH") and not f.get("ast_source"):
                self.log("INFO", f"   🛡️  تحقق: {f['name']}")
                f["validation"] = validate_token(f)
                time.sleep(0.2)
        return findings

    # ── Main Run ─────────────────────────────────────────────────
    def run(self, target_url, do_validate, do_browser, do_subdomain,
            do_hidden, do_ast, timeout, workers, recursive_depth,
            tg_token, tg_chat, notify_desktop, done_cb):

        self.results = []; self.stop_flag = False
        if not urlparse(target_url).scheme:
            target_url = "https://" + target_url

        # 1. Crawl
        self.status("🕷️  Crawling…")
        ext_urls, inlines, map_urls = self.crawl(target_url, timeout, recursive_depth)
        total = len(ext_urls)+len(inlines)+len(map_urls)
        self.prog(0, max(total,1))

        # 2. Fetch
        self.status("⬇️  Fetching JS files…")
        fetched = self.fetch_all(ext_urls, timeout, workers)

        # 3. Scan
        self.log("INFO","[3/6] 🔎 Regex + Deobfuscation + AST + Context Filter…")
        all_findings, done = [], 0

        for i, code in enumerate(inlines, 1):
            if self.stop_flag: break
            label = f"Inline #{i}"
            self.status(f"Scanning {label}…")
            found = self.scan_content(code, label)
            if found: self.log("MEDIUM", f"   🎯 {label}: {len(found)} نتيجة")
            all_findings.extend(found); done += 1; self.prog(done, max(total,1))

        for url, code in fetched.items():
            if self.stop_flag: break
            short = url.split("/")[-1][:45] or url[-45:]
            lines = code.count("\n") if code else 0
            self.status(f"Scanning {short} ({lines} lines)…")
            self.log("INFO", f"   🔍 {short} ({lines} lines)")
            if code:
                sm = re.search(r"//# sourceMappingURL=([^\s]+)", code)
                if sm:
                    mu = urljoin(url, sm.group(1))
                    if mu not in map_urls: map_urls.append(mu)
                found = self.scan_content(code, url)
                if found:
                    ms = min(SEVERITY_ORDER.get(x["severity"],9) for x in found)
                    st = ["CRITICAL","HIGH","MEDIUM","LOW"][ms] if ms < 4 else "INFO"
                    self.log(st, f"   🎯 {short}: {len(found)} نتيجة")
                all_findings.extend(found)
            done += 1; self.prog(done, max(total,1))

        # 4. Source Maps
        self.log("INFO","[4/6] 🗺️  Source Maps…")
        self.status("Processing Source Maps…")
        if map_urls:
            map_contents = self.fetch_all(map_urls, timeout, workers)
            for mu, mc in map_contents.items():
                if self.stop_flag: break
                if mc and mc.strip().startswith("{"):
                    self.log("INFO", f"   📦 {mu.split('/')[-1][:40]}")
                    for src_code, src_label in self.extract_from_sourcemap(mc, mu):
                        found = self.scan_content(src_code, src_label)
                        if found:
                            self.log("HIGH",
                                f"   🎯 {src_label}: {len(found)} نتيجة في الكود الأصلي!")
                        all_findings.extend(found)
                done += 1; self.prog(done, max(total,1))

        # 5. Hidden Assets
        if do_hidden:
            self.status("Discovering hidden assets…")
            for url, content, fname in self.discover_hidden_assets(target_url, timeout):
                if self.stop_flag: break
                found = self.scan_content(content, f"[Hidden] {fname}")
                if found:
                    self.log("CRITICAL",
                        f"   💎 {fname}: {len(found)} سر في ملف مخفي!")
                all_findings.extend(found)

        # 6. Network Interception
        if do_browser:
            self.status("Network interception + Browser storage…")
            all_findings.extend(self.intercept_network(target_url, timeout))

        # Dedup + Sort
        seen, unique = set(), []
        for f in all_findings:
            key = (f["name"], f["value"][:40].lower())
            if key not in seen: seen.add(key); unique.append(f)
        unique.sort(key=lambda x:(SEVERITY_ORDER.get(x["severity"],9), x["name"]))

        # Subdomain
        if do_subdomain and unique:
            self.status("Subdomain scanning…")
            for f in self.scan_subdomains(unique, timeout, workers):
                key = (f["name"], f["value"][:40].lower())
                if key not in seen: seen.add(key); unique.append(f)
            unique.sort(key=lambda x:(SEVERITY_ORDER.get(x["severity"],9), x["name"]))

        # Validate
        if do_validate and unique:
            n = sum(1 for f in unique if f["severity"] in ("CRITICAL","HIGH") and not f.get("ast_source"))
            self.log("INFO", f"[6/6] 🛡️  تحقق من {n} توكن…")
            self.status("Live validation…")
            self.validate_all(unique)
        else:
            self.log("INFO","[6/6] ⏭️  تخطي التحقق")

        # Notifications
        crits = [f for f in unique if f["severity"]=="CRITICAL"]
        if crits:
            msg = (f"🚨 {len(crits)} CRITICAL في {urlparse(target_url).netloc}\n"
                   + "\n".join(f"• {f['name']}: {f['value'][:50]}" for f in crits[:5]))
            if notify_desktop: desktop_notify("🔐 JS Secret Hunter v4!", msg)
            if tg_token and tg_chat:
                tg = (f"🚨 <b>CRITICAL ALERT — JS Secret Hunter v4</b>\n"
                      f"🎯 <code>{target_url}</code>\n\n")
                for f in crits[:8]:
                    tg += (f"🔴 <b>{html_mod.escape(f['name'])}</b>\n"
                           f"└ <code>{html_mod.escape(f['value'][:80])}</code>\n"
                           f"└ {f.get('validation','—')}\n\n")
                ok = telegram_notify(tg_token, tg_chat, tg)
                self.log("INFO" if ok else "HIGH",
                    "✅ Telegram أُرسل" if ok else "❌ فشل Telegram")

        self.status("✅ اكتمل")
        self.results = unique
        done_cb(unique, target_url)

# ══════════════════════════════════════════════════════════════════
#  HTML REPORT
# ══════════════════════════════════════════════════════════════════
def generate_html_report(findings, target_url, counts, risk, ts):
    sev_badge = {"CRITICAL":"#FF2244","HIGH":"#FF8C00","MEDIUM":"#FFD700","LOW":"#00BFFF"}
    rows = ""
    for i, f in enumerate(findings, 1):
        color = sev_badge.get(f["severity"],"#888")
        gold  = f.get("is_golden",False)
        ast_m = " 🌳" if f.get("ast_source") else ""
        rows += f"""<tr style="{'background:#1a1400;' if gold else ''}">
          <td>{i}</td>
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td>{html_mod.escape(f['name'])}{ast_m}</td>
          <td>{html_mod.escape(f.get('svc',''))}</td>
          <td class="mono">{html_mod.escape(f.get('value',''))}</td>
          <td class="mono small">{html_mod.escape(f.get('context',''))}</td>
          <td style="{'color:#FFD700;font-weight:bold' if gold else ''}">{html_mod.escape(f.get('entropy',''))}</td>
          <td>{html_mod.escape(f.get('validation','—'))}</td>
          <td class="small">{html_mod.escape(f.get('source','').split('/')[-1][:35])}</td>
        </tr>"""

    rc = "#FF2244" if risk>=70 else "#FF8C00" if risk>=40 else "#FFD700" if risk>=15 else "#00BFFF"
    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>JS Secret Hunter v4 — تقرير</title>
<style>
*{{box-sizing:border-box}}body{{font-family:'Segoe UI',Consolas,monospace;background:#080812;color:#ccd;margin:0;padding:24px}}
h1{{color:#00FF88;text-align:center;font-size:1.6em;margin-bottom:4px}}.meta{{text-align:center;color:#445;font-size:13px;margin-bottom:20px}}
.summary{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}.card{{background:#12121e;border:1px solid #223;border-radius:8px;padding:14px 20px;flex:1;min-width:120px;text-align:center}}
.card .num{{font-size:2em;font-weight:bold}}.crit{{color:#FF2244}}.high{{color:#FF8C00}}.med{{color:#FFD700}}.low{{color:#00BFFF}}
.risk-fill{{height:20px;border-radius:6px}}table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#12121e;color:#00FF88;padding:9px;text-align:right;border-bottom:2px solid #00FF8830;white-space:nowrap}}
td{{padding:7px;border-bottom:1px solid #1a1a2e;vertical-align:top}}tr:hover{{background:#12121e55}}
.badge{{padding:2px 8px;border-radius:4px;font-weight:bold;color:#000;font-size:11px}}.mono{{font-family:Consolas,monospace;word-break:break-all}}
.small{{font-size:11px;color:#556}}input#s{{background:#12121e;border:1px solid #334;color:#ccd;padding:6px 12px;border-radius:6px;width:300px;font-size:13px;margin-bottom:12px}}
footer{{text-align:center;color:#334;margin-top:30px;font-size:12px}}
</style>
<script>function f(){{var q=document.getElementById('s').value.toLowerCase();document.querySelectorAll('tbody tr').forEach(function(r){{r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';}});}}</script>
</head><body>
<h1>🔐 JS Secret Hunter v4 — تقرير الفحص الأمني</h1>
<p class="meta">الهدف: <strong style="color:#adf">{html_mod.escape(target_url)}</strong> | {ts}</p>
<div class="summary">
  <div class="card"><div class="num crit">{counts.get('CRITICAL',0)}</div><div>CRITICAL</div></div>
  <div class="card"><div class="num high">{counts.get('HIGH',0)}</div><div>HIGH</div></div>
  <div class="card"><div class="num med">{counts.get('MEDIUM',0)}</div><div>MEDIUM</div></div>
  <div class="card"><div class="num low">{counts.get('LOW',0)}</div><div>LOW</div></div>
  <div class="card"><div class="num" style="color:{rc}">{risk}/100</div><div>مؤشر الخطورة</div></div>
  <div class="card"><div class="num" style="color:#FFD700">{sum(1 for f in findings if f.get('is_golden'))}</div><div>🌟 Entropy عالية</div></div>
  <div class="card"><div class="num" style="color:#00FF88">{sum(1 for f in findings if f.get('ast_source'))}</div><div>🌳 AST</div></div>
</div>
<div style="background:#12121e;border-radius:8px;padding:16px;margin-bottom:20px">
  <div style="color:{rc};font-weight:bold;margin-bottom:8px">مؤشر الخطورة: {risk}/100</div>
  <div style="background:#1a1a2e;border-radius:6px"><div class="risk-fill" style="width:{risk}%;background:{rc}"></div></div>
</div>
<input id="s" type="text" placeholder="🔍 بحث في النتائج…" oninput="f()">
<table><thead><tr>
  <th>#</th><th>الخطورة</th><th>النوع</th><th>الخدمة</th><th>القيمة</th>
  <th>السياق</th><th>Entropy</th><th>التحقق</th><th>المصدر</th>
</tr></thead><tbody>{rows}</tbody></table>
<footer>⚠️ للاستخدام الأخلاقي المرخص فقط — JS Secret Hunter v4 | 🌳 = AST | 🌟 = Entropy ≥ {ENTROPY_GOLD}</footer>
</body></html>"""

# ══════════════════════════════════════════════════════════════════
#  SETTINGS DIALOG
# ══════════════════════════════════════════════════════════════════
class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("⚙️  الإعدادات المتقدمة — v4")
        self.geometry("560x520")
        self.configure(bg="#090912")
        self.resizable(False,False)
        self.result = None
        self._build(parent); self.grab_set()

    def _lbl(self,p,t,**kw):
        kw.setdefault("bg","#090912"); kw.setdefault("fg","#99AABB")
        kw.setdefault("font",("Consolas",10))
        return tk.Label(p,text=t,**kw)

    def _build(self, parent):
        self._lbl(self,"⚙️  إعدادات متقدمة — JS Secret Hunter v4",
                  fg="#00FF88",font=("Consolas",12,"bold")).pack(padx=16,pady=(14,6))

        # Telegram
        tf = tk.LabelFrame(self,text=" 🤖 Telegram Bot ",bg="#090912",
                           fg="#00FF88",font=("Consolas",10,"bold"),bd=1,relief="groove")
        tf.pack(fill="x",padx=14,pady=4)
        self._lbl(tf,"Bot Token:").grid(row=0,column=0,sticky="w",padx=8,pady=3)
        self.tg_token = tk.StringVar(value=getattr(parent,"_tg_token",""))
        tk.Entry(tf,textvariable=self.tg_token,width=40,bg="#0d0d1a",fg="#00FF88",
                 insertbackground="#00FF88",relief="flat",
                 font=("Consolas",9)).grid(row=0,column=1,padx=6,pady=3)
        self._lbl(tf,"Chat ID:").grid(row=1,column=0,sticky="w",padx=8,pady=3)
        self.tg_chat = tk.StringVar(value=getattr(parent,"_tg_chat",""))
        tk.Entry(tf,textvariable=self.tg_chat,width=40,bg="#0d0d1a",fg="#00FF88",
                 insertbackground="#00FF88",relief="flat",
                 font=("Consolas",9)).grid(row=1,column=1,padx=6,pady=3)
        tk.Button(tf,text="🧪 اختبار",command=self._test_tg,
                  bg="#1a2a3a",fg="#99AABB",relief="flat",
                  font=("Consolas",9),cursor="hand2",padx=8
                  ).grid(row=2,column=1,sticky="w",padx=6,pady=4)

        # Features
        ff = tk.LabelFrame(self,text=" 🔧 ميزات الفحص ",bg="#090912",
                           fg="#00FF88",font=("Consolas",10,"bold"),bd=1,relief="groove")
        ff.pack(fill="x",padx=14,pady=4)

        opts = [
            ("_notify_desktop", "🔔 تنبيهات سطح المكتب", True, True),
            ("_do_browser",
             "🌐 Network Interception + Browser Storage (Playwright)" +
             (" ✅" if HAS_PLAYWRIGHT else " ❌"), HAS_PLAYWRIGHT, HAS_PLAYWRIGHT),
            ("_do_subdomain",   "🌍 فحص الروابط الفرعية (Subdomain)", True, True),
            ("_do_hidden",      "📁 Hidden Assets Discovery (.env, config…)", True, True),
            ("_do_ast",
             "🌳 AST Analysis" + (" + pyjsparser ✅" if HAS_AST else " (Regex fallback)"),
             True, True),
        ]
        self._vars = {}
        for attr, label, default, enabled in opts:
            v = tk.BooleanVar(value=getattr(parent, attr, default))
            self._vars[attr] = v
            cb = tk.Checkbutton(ff,text=label,variable=v,
                                bg="#090912",fg="#99AABB",
                                selectcolor="#0d0d1a",
                                font=("Consolas",10),
                                state="normal" if enabled else "disabled")
            cb.pack(anchor="w",padx=8,pady=2)

        # Scan depth
        df = tk.Frame(ff,bg="#090912"); df.pack(anchor="w",padx=8,pady=4)
        self._lbl(df,"عمق Recursive Crawl:").pack(side="left",padx=(0,4))
        self.rec_depth = tk.IntVar(value=getattr(parent,"_rec_depth",1))
        tk.Spinbox(df,from_=0,to=3,textvariable=self.rec_depth,
                   width=3,bg="#0d0d1a",fg="#99AABB",relief="flat",
                   font=("Consolas",10)).pack(side="left")

        # Buttons
        bf = tk.Frame(self,bg="#090912"); bf.pack(pady=14)
        tk.Button(bf,text="✅ حفظ",command=self._save,
                  bg="#00AA55",fg="#001100",font=("Consolas",11,"bold"),
                  relief="flat",padx=16,pady=4).pack(side="left",padx=8)
        tk.Button(bf,text="✖ إلغاء",command=self.destroy,
                  bg="#331122",fg="#FF8888",font=("Consolas",10),
                  relief="flat",padx=12,pady=4).pack(side="left")

    def _test_tg(self):
        ok = telegram_notify(self.tg_token.get().strip(),
                             self.tg_chat.get().strip(),
                             "🧪 اختبار JS Secret Hunter v4 — يعمل ✅")
        messagebox.showinfo("Telegram",
            "✅ تم الإرسال" if ok else "❌ فشل — تحقق من Token و Chat ID")

    def _save(self):
        self.result = {k: v.get() for k, v in self._vars.items()}
        self.result["tg_token"]  = self.tg_token.get().strip()
        self.result["tg_chat"]   = self.tg_chat.get().strip()
        self.result["rec_depth"] = self.rec_depth.get()
        self.destroy()

# ══════════════════════════════════════════════════════════════════
#  MAIN GUI
# ══════════════════════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 JS Secret Hunter v4 — أداة الأمن السيبراني")
        self.geometry("1360x900")
        self.minsize(1050,680)
        self.configure(bg="#090912")
        self._findings_cache  = {}
        self._all_findings    = []
        self.scanner          = None
        self._tg_token        = ""
        self._tg_chat         = ""
        self._notify_desktop  = True
        self._do_browser      = False
        self._do_subdomain    = True
        self._do_hidden       = True
        self._do_ast          = True
        self._rec_depth       = 1
        self._scan_start_time = None
        self._build_style()
        self._build_ui()

    def _build_style(self):
        s = ttk.Style(); s.theme_use("clam")
        s.configure("green.Horizontal.TProgressbar",
                    troughcolor="#12121e",background="#00FF88",thickness=10)
        s.configure("Treeview",background="#090912",foreground="#99AABB",
                    fieldbackground="#090912",rowheight=24,font=("Consolas",9))
        s.configure("Treeview.Heading",background="#12121e",foreground="#00FF88",
                    font=("Consolas",9,"bold"),relief="flat")
        s.map("Treeview",background=[("selected","#1a2a3a")],
              foreground=[("selected","#ffffff")])

    def _lbl(self,p,t,**kw):
        kw.setdefault("bg","#090912"); kw.setdefault("fg","#99AABB")
        kw.setdefault("font",("Consolas",10))
        return tk.Label(p,text=t,**kw)

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self,bg="#090912"); hdr.pack(fill="x",padx=16,pady=(12,4))
        self._lbl(hdr,"🔐 JS Secret Hunter v4",fg="#00FF88",
                  font=("Consolas",17,"bold")).pack(side="left")
        self._lbl(hdr,"  AST • Deobfuscation • Network Interception • Hidden Assets",
                  fg="#1a2a3a",font=("Consolas",9)).pack(side="left",pady=2)
        missing = [x for x,h in [("jsbeautifier",HAS_BEAUTIFIER),
                                   ("playwright",HAS_PLAYWRIGHT),
                                   ("pyjsparser",HAS_AST)] if not h]
        if missing:
            self._lbl(hdr,f"  ⚠️ {', '.join(missing)}",fg="#FF8C00",
                      font=("Consolas",9)).pack(side="right")

        # Input
        inp = tk.Frame(self,bg="#090912"); inp.pack(fill="x",padx=16,pady=4)
        self._lbl(inp,"🌐").pack(side="left")
        self.url_var = tk.StringVar(value="https://")
        tk.Entry(inp,textvariable=self.url_var,width=48,font=("Consolas",11),
                 bg="#0d0d1a",fg="#00FF88",insertbackground="#00FF88",relief="flat",
                 highlightthickness=1,highlightcolor="#00FF88",
                 highlightbackground="#1a2233").pack(side="left",padx=6,ipady=5)
        for lbl, var, default, rng in [
            ("Timeout:", "timeout_var", 12, (3,60)),
            ("Workers:", "workers_var", 10, (1,30)),
        ]:
            self._lbl(inp,f"  {lbl}").pack(side="left",padx=(4,2))
            setattr(self, var, tk.IntVar(value=default))
            tk.Spinbox(inp,from_=rng[0],to=rng[1],
                       textvariable=getattr(self,var),
                       width=4,bg="#0d0d1a",fg="#99AABB",
                       buttonbackground="#1a1a2e",relief="flat",
                       font=("Consolas",10)).pack(side="left")

        self.validate_var = tk.BooleanVar(value=True)
        tk.Checkbutton(inp,text=" 🛡️ تحقق",variable=self.validate_var,
                       font=("Consolas",10),fg="#99AABB",bg="#090912",
                       selectcolor="#0d0d1a",activebackground="#090912",
                       activeforeground="#00FF88").pack(side="left",padx=6)

        self.start_btn = tk.Button(inp,text="▶  ابدأ الفحص",
                                   command=self._start_scan,
                                   font=("Consolas",11,"bold"),
                                   bg="#00AA55",fg="#001100",relief="flat",
                                   padx=14,pady=4,cursor="hand2",
                                   activebackground="#00DD77")
        self.start_btn.pack(side="left",padx=4)
        self.stop_btn = tk.Button(inp,text="⏹ إيقاف",command=self._stop_scan,
                                  font=("Consolas",10),bg="#AA2222",fg="white",
                                  relief="flat",padx=10,pady=4,cursor="hand2",
                                  state="disabled")
        self.stop_btn.pack(side="left",padx=2)
        tk.Button(inp,text="⚙️",command=self._open_settings,
                  font=("Consolas",12),bg="#1a2233",fg="#99AABB",
                  relief="flat",padx=8,pady=3,cursor="hand2"
                  ).pack(side="left",padx=4)

        # Status bar (Feature ⑥)
        sb = tk.Frame(self,bg="#090912"); sb.pack(fill="x",padx=16,pady=2)
        self.status_var = tk.StringVar(value="جاهز")
        tk.Label(sb,textvariable=self.status_var,
                 bg="#111120",fg="#00FF88",anchor="w",
                 font=("Consolas",9),relief="flat",padx=8
                 ).pack(fill="x",ipady=3)

        # Filter
        fil = tk.Frame(self,bg="#090912"); fil.pack(fill="x",padx=16,pady=2)
        self._lbl(fil,"🔍",fg="#445566").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write",self._apply_filter)
        tk.Entry(fil,textvariable=self.filter_var,width=22,font=("Consolas",10),
                 bg="#0d0d1a",fg="#99AABB",insertbackground="#99AABB",relief="flat",
                 highlightthickness=1,highlightcolor="#334455",
                 highlightbackground="#1a2233").pack(side="left",padx=4,ipady=3)
        self._lbl(fil,"الخطورة:",fg="#445566").pack(side="left",padx=(8,2))
        self.sev_var = tk.StringVar(value="الكل")
        sc = ttk.Combobox(fil,textvariable=self.sev_var,
                          values=["الكل","CRITICAL","HIGH","MEDIUM","LOW"],
                          width=9,font=("Consolas",10),state="readonly")
        sc.pack(side="left"); sc.bind("<<ComboboxSelected>>",lambda _:self._apply_filter())
        self._lbl(fil,"الخدمة:",fg="#445566").pack(side="left",padx=(8,2))
        self.svc_var = tk.StringVar(value="الكل")
        svcs = ["الكل"]+sorted({p["svc"] for p in SECRET_PATTERNS})+["AST","BrowserStorage","NetworkInterception","Cookie"]
        vc = ttk.Combobox(fil,textvariable=self.svc_var,
                          values=svcs,width=16,font=("Consolas",10),state="readonly")
        vc.pack(side="left"); vc.bind("<<ComboboxSelected>>",lambda _:self._apply_filter())
        self.gold_only = tk.BooleanVar(value=False)
        tk.Checkbutton(fil,text=" 🌟 Entropy فقط",variable=self.gold_only,
                       command=self._apply_filter,font=("Consolas",10),fg="#FFD700",
                       bg="#090912",selectcolor="#0d0d1a",
                       activebackground="#090912").pack(side="left",padx=6)
        self.ast_only = tk.BooleanVar(value=False)
        tk.Checkbutton(fil,text=" 🌳 AST فقط",variable=self.ast_only,
                       command=self._apply_filter,font=("Consolas",10),fg="#88FFCC",
                       bg="#090912",selectcolor="#0d0d1a",
                       activebackground="#090912").pack(side="left",padx=4)

        # Progress (Feature ⑥)
        pf = tk.Frame(self,bg="#090912"); pf.pack(fill="x",padx=16,pady=2)
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(pf,variable=self.progress_var,maximum=100,
                        style="green.Horizontal.TProgressbar"
                        ).pack(side="left",fill="x",expand=True)
        self.prog_label = self._lbl(pf,"جاهز",fg="#334455",width=26)
        self.prog_label.pack(side="left",padx=6)
        self.timer_label = self._lbl(pf,"",fg="#445566",width=10)
        self.timer_label.pack(side="left")

        # Paned
        paned = tk.PanedWindow(self,orient="horizontal",bg="#090912",
                               sashwidth=5,sashrelief="flat",sashpad=2)
        paned.pack(fill="both",expand=True,padx=8,pady=4)

        # LEFT: Log
        left = tk.Frame(paned,bg="#090912"); paned.add(left,minsize=270)
        self._lbl(left,"📋 سجل العمليات",fg="#00FF88",
                  font=("Consolas",11,"bold")).pack(anchor="w",padx=4)
        self.log_box = scrolledtext.ScrolledText(
            left,font=("Consolas",9),bg="#060610",fg="#334455",
            insertbackground="#00FF88",relief="flat",state="disabled",
            wrap="word",selectbackground="#1a2a3a")
        self.log_box.pack(fill="both",expand=True,padx=2,pady=2)
        for sev,col in SEVERITY_COLORS.items():
            self.log_box.tag_config(sev,foreground=col)
        self.log_box.tag_config("GOLDEN",foreground="#FFD700",font=("Consolas",9,"bold"))
        self.log_box.tag_config("AST",foreground="#88FFCC")

        # RIGHT: Results
        right = tk.Frame(paned,bg="#090912"); paned.add(right,minsize=540)
        top_r = tk.Frame(right,bg="#090912"); top_r.pack(fill="x")
        self._lbl(top_r,"🎯 نتائج الفحص",fg="#00FF88",
                  font=("Consolas",11,"bold")).pack(side="left",padx=4)
        self.result_count = self._lbl(top_r,"",fg="#334455"); self.result_count.pack(side="left")
        bf2 = tk.Frame(top_r,bg="#090912"); bf2.pack(side="right")
        for txt,cmd in [("💾 TXT",lambda:self._save("txt")),
                        ("📋 JSON",lambda:self._save("json")),
                        ("🌐 HTML",lambda:self._save("html"))]:
            tk.Button(bf2,text=txt,command=cmd,font=("Consolas",9),bg="#12121e",
                      fg="#99AABB",relief="flat",padx=8,pady=2,
                      cursor="hand2").pack(side="left",padx=2)

        # Treeview
        cols = ("severity","svc","name","value","entropy","validation","source")
        self.tree = ttk.Treeview(right,columns=cols,show="headings",selectmode="browse")
        for cid,hd,w in [
            ("severity","الخطورة",78),("svc","الخدمة",90),
            ("name","النوع",165),("value","القيمة",240),
            ("entropy","Entropy",130),("validation","التحقق",165),
            ("source","المصدر",100)]:
            self.tree.heading(cid,text=hd,command=lambda c=cid:self._sort_tree(c))
            self.tree.column(cid,width=w,minwidth=50,anchor="w")
        vsb = ttk.Scrollbar(right,orient="vertical",command=self.tree.yview)
        hsb = ttk.Scrollbar(right,orient="horizontal",command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,xscrollcommand=hsb.set)
        self.tree.pack(side="left",fill="both",expand=True)
        vsb.pack(side="right",fill="y"); hsb.pack(side="bottom",fill="x")
        self.tree.bind("<<TreeviewSelect>>",self._on_select)

        # Stats mini-panel (Feature ⑥)
        stats_f = tk.Frame(self,bg="#0a0a18"); stats_f.pack(fill="x",padx=8,pady=(0,2))
        self.stat_labels = {}
        for sev,col,icon in [("CRITICAL","#FF2244","🔴"),("HIGH","#FF8C00","🟠"),
                              ("MEDIUM","#FFD700","🟡"),("LOW","#00BFFF","🔵"),
                              ("AST","#88FFCC","🌳"),("GOLDEN","#FFD700","🌟"),
                              ("OPEN_BUCKET","#FF2244","🚨")]:
            lf = tk.Frame(stats_f,bg="#0a0a18"); lf.pack(side="left",padx=8,pady=3)
            tk.Label(lf,text=icon,bg="#0a0a18",font=("Consolas",10)
                     ).pack(side="left")
            v = tk.StringVar(value="0")
            tk.Label(lf,textvariable=v,fg=col,bg="#0a0a18",
                     font=("Consolas",10,"bold")).pack(side="left")
            self.stat_labels[sev] = v

        # Detail
        dp = tk.Frame(self,bg="#090912"); dp.pack(fill="x",padx=8,pady=(0,4))
        self._lbl(dp,"🔍 التفاصيل:",fg="#334455").pack(side="left")
        self.detail_box = tk.Text(dp,height=4,font=("Consolas",9),
                                  bg="#08080f",fg="#99AABB",relief="flat",
                                  wrap="word",state="disabled")
        self.detail_box.pack(fill="x",expand=True,padx=4)

    # ── Controls ─────────────────────────────────────────────────
    def _open_settings(self):
        dlg = SettingsDialog(self); self.wait_window(dlg)
        if dlg.result:
            r = dlg.result
            self._tg_token       = r.get("tg_token","")
            self._tg_chat        = r.get("tg_chat","")
            self._notify_desktop = r.get("_notify_desktop",True)
            self._do_browser     = r.get("_do_browser",False)
            self._do_subdomain   = r.get("_do_subdomain",True)
            self._do_hidden      = r.get("_do_hidden",True)
            self._do_ast         = r.get("_do_ast",True)
            self._rec_depth      = r.get("rec_depth",1)
            self._log("INFO","✅ تم حفظ الإعدادات")

    def _start_scan(self):
        url = self.url_var.get().strip()
        if not url or url in ("https://","http://"):
            messagebox.showwarning("تنبيه","الرجاء إدخال رابط الهدف"); return
        if not messagebox.askyesno("⚠️  تأكيد قانوني",
            "هذه الأداة للاختبار على المواقع التي تملك إذناً قانونياً بفحصها.\n\n"
            "هل تؤكد أن لديك صلاحية فحص هذا الهدف؟",icon="warning"):
            return

        self.tree.delete(*self.tree.get_children()); self._findings_cache.clear()
        self._all_findings = []
        self.log_box.configure(state="normal"); self.log_box.delete("1.0","end")
        self.log_box.configure(state="disabled")
        self.result_count.config(text="")
        self.detail_box.configure(state="normal"); self.detail_box.delete("1.0","end")
        self.detail_box.configure(state="disabled")
        self.progress_var.set(0); self.prog_label.config(text="جارٍ الفحص…")
        self.status_var.set("جارٍ التهيئة…")
        for v in self.stat_labels.values(): v.set("0")
        self.start_btn.configure(state="disabled"); self.stop_btn.configure(state="normal")
        self._scan_start_time = time.time()
        self._start_timer()

        self.scanner = Scanner(self._log, self._update_progress, self._update_status)
        threading.Thread(
            target=self.scanner.run,
            args=(url, self.validate_var.get(),
                  self._do_browser, self._do_subdomain,
                  self._do_hidden, self._do_ast,
                  self.timeout_var.get(), self.workers_var.get(),
                  self._rec_depth, self._tg_token, self._tg_chat,
                  self._notify_desktop, self._on_done),
            daemon=True).start()

    def _start_timer(self):
        def _tick():
            if self._scan_start_time and self.start_btn["state"] == "disabled":
                elapsed = int(time.time() - self._scan_start_time)
                m, s = divmod(elapsed, 60)
                self.timer_label.config(text=f"⏱ {m:02d}:{s:02d}")
                self.after(1000, _tick)
            else:
                elapsed = int(time.time() - self._scan_start_time) if self._scan_start_time else 0
                m, s = divmod(elapsed, 60)
                self.timer_label.config(text=f"⏱ {m:02d}:{s:02d}")
        self.after(1000, _tick)

    def _stop_scan(self):
        if self.scanner: self.scanner.stop_flag = True; self._log("INFO","⏹ إيقاف…")
        self.stop_btn.configure(state="disabled")

    def _log(self, sev, msg):
        def _do():
            self.log_box.configure(state="normal")
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            tag = "GOLDEN" if "🌟" in msg else ("AST" if "AST" in msg or "🌳" in msg else sev)
            self.log_box.insert("end",f"[{ts}] {msg}\n",tag)
            self.log_box.see("end"); self.log_box.configure(state="disabled")
        self.after(0,_do)

    def _update_progress(self, done, total):
        pct = int(done/total*100) if total else 0
        def _do():
            self.progress_var.set(pct)
            self.prog_label.config(text=f"{done}/{total}  ({pct}%)")
        self.after(0,_do)

    def _update_status(self, msg):
        self.after(0, lambda: self.status_var.set(f"  ⚡ {msg}"))

    def _on_done(self, findings, target_url):
        def _do():
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.prog_label.config(text="✅ اكتمل")
            self.status_var.set("  ✅ اكتمل الفحص")
            self.progress_var.set(100)
            self._all_findings = findings
            self._populate_tree(findings)

            counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
            for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
            risk = self._risk_score(counts)

            # Update mini stats
            for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
                self.stat_labels[sev].set(str(counts.get(sev,0)))
            self.stat_labels["AST"].set(str(sum(1 for f in findings if f.get("ast_source"))))
            self.stat_labels["GOLDEN"].set(str(sum(1 for f in findings if f.get("is_golden"))))
            self.stat_labels["OPEN_BUCKET"].set(
                str(sum(1 for f in findings if "OPEN" in f.get("validation",""))))

            self.result_count.config(
                text=f"  — {len(findings)} نتيجة",
                fg="#FF2244" if counts["CRITICAL"]>0 else "#00FF88")
            self._log("INFO",
                f"✅ انتهى — 🔴{counts['CRITICAL']} 🟠{counts['HIGH']} "
                f"🟡{counts['MEDIUM']} 🔵{counts['LOW']} │ {risk}/100")
            self._auto_save(findings, target_url, counts, risk)
        self.after(0,_do)

    def _populate_tree(self, findings):
        self.tree.delete(*self.tree.get_children()); self._findings_cache.clear()
        filt = self.filter_var.get().lower()
        fsev = self.sev_var.get(); fsvc = self.svc_var.get()
        gold = self.gold_only.get(); ast_f = self.ast_only.get()

        for f in findings:
            if fsev not in ("الكل",f["severity"]): continue
            if fsvc not in ("الكل",f.get("svc","")): continue
            if gold and not f.get("is_golden"): continue
            if ast_f and not f.get("ast_source"): continue
            if filt and filt not in json.dumps(f,ensure_ascii=False).lower(): continue

            sev = f["severity"]
            tag = "GOLDEN" if f.get("is_golden") else sev
            rid = self.tree.insert("","end",
                values=(f"[{sev}]",f.get("svc",""),
                        ("🌳 " if f.get("ast_source") else "")+f["name"],
                        f["value"],f.get("entropy",""),
                        f.get("validation","—"),
                        f["source"].split("/")[-1][:35]),
                tags=(tag,))
            self._findings_cache[rid] = f

        for sev,col in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev,foreground=col)
        self.tree.tag_configure("GOLDEN",foreground="#FFD700",font=("Consolas",9,"bold"))
        self.tree.tag_configure("AST",foreground="#88FFCC")

    def _apply_filter(self,*_):
        if self._all_findings: self._populate_tree(self._all_findings)

    def _sort_tree(self, col):
        data = [(self.tree.set(k,col),k) for k in self.tree.get_children("")]
        data.sort(reverse=getattr(self,f"_sr_{col}",False))
        for i,(_,k) in enumerate(data): self.tree.move(k,"",i)
        setattr(self,f"_sr_{col}",not getattr(self,f"_sr_{col}",False))

    def _on_select(self,_):
        sel = self.tree.selection()
        if not sel: return
        f = self._findings_cache.get(sel[0])
        if not f: return
        self.detail_box.configure(state="normal"); self.detail_box.delete("1.0","end")
        ast_note = "  🌳 مكتشف بالـ AST" if f.get("ast_source") else ""
        lines = [
            f"[{f['severity']}] {f['name']}  |  الخدمة: {f.get('svc','')}  |  {f.get('entropy','')}{ast_note}",
            f"القيمة  : {f['value']}",
            f"التحقق  : {f.get('validation','—')}",
            f"المصدر  : {f['source']}",
            f"السياق  : {f.get('context','—')}",
        ]
        self.detail_box.insert("end","\n".join(lines))
        self.detail_box.configure(state="disabled")

    def _risk_score(self, counts):
        return min(100,counts.get("CRITICAL",0)*30+counts.get("HIGH",0)*15+
                   counts.get("MEDIUM",0)*5+counts.get("LOW",0)*1)

    def _auto_save(self, findings, target_url, counts, risk):
        ts     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(target_url).netloc.replace(".","_")
        base   = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              f"jsh_{domain}_{ts}")
        ts_h   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write_txt(findings,target_url,counts,risk,base+".txt",ts_h)
        with open(base+".html","w",encoding="utf-8") as fh:
            fh.write(generate_html_report(findings,target_url,counts,risk,ts_h))
        self._log("INFO",f"💾 حُفظ: {os.path.basename(base)}.txt / .html")

    def _save(self, fmt):
        if not self._all_findings:
            messagebox.showinfo("تنبيه","لا توجد نتائج."); return
        findings = self._all_findings
        counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
        risk = self._risk_score(counts)
        ts_h = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(),f"*.{fmt}"),("All","*.*")])
        if not path: return
        if fmt=="json":
            with open(path,"w",encoding="utf-8") as fh:
                json.dump(findings,fh,ensure_ascii=False,indent=2)
        elif fmt=="html":
            with open(path,"w",encoding="utf-8") as fh:
                fh.write(generate_html_report(findings,self.url_var.get(),counts,risk,ts_h))
        else:
            self._write_txt(findings,self.url_var.get(),counts,risk,path,ts_h)
        messagebox.showinfo("تم ✅",f"حُفظ في:\n{path}")

    def _write_txt(self, findings, target_url, counts, risk, path, ts_h):
        golden = sum(1 for f in findings if f.get("is_golden"))
        ast_cnt = sum(1 for f in findings if f.get("ast_source"))
        open_b  = sum(1 for f in findings if "OPEN" in f.get("validation",""))
        elapsed = int(time.time()-self._scan_start_time) if self._scan_start_time else 0
        m, s = divmod(elapsed, 60)
        lines = [
            "="*74,
            "  JS SECRET HUNTER v4 — تقرير الفحص الأمني",
            "="*74,
            f"الهدف                   : {target_url}",
            f"تاريخ الفحص             : {ts_h}",
            f"مدة الفحص               : {m:02d}:{s:02d}",
            f"إجمالي النتائج          : {len(findings)}",
            f"مفاتيح Entropy عالية    : {golden} 🌟",
            f"نتائج AST               : {ast_cnt} 🌳",
            f"Cloud Buckets مفتوحة    : {open_b} 🚨",
            f"مؤشر الخطورة الكلي      : {risk}/100",
            "",
            f"  🔴 CRITICAL : {counts.get('CRITICAL',0)}",
            f"  🟠 HIGH     : {counts.get('HIGH',0)}",
            f"  🟡 MEDIUM   : {counts.get('MEDIUM',0)}",
            f"  🔵 LOW      : {counts.get('LOW',0)}",
            "="*74,"",
        ]
        for i,f in enumerate(findings,1):
            marks = ("🌟" if f.get("is_golden") else "") + \
                    (" 🌳" if f.get("ast_source") else "")
            lines += [
                f"[{i:03d}] [{f['severity']}] {f['name']}  ({f.get('svc','')}){marks}",
                f"       القيمة   : {f['value']}",
                f"       Entropy  : {f.get('entropy','')}",
                f"       التحقق   : {f.get('validation','—')}",
                f"       المصدر   : {f['source']}",
                f"       السياق   : {f.get('context','—')[:250]}","",
            ]
        lines += ["="*74,
                  "⚠️  للاستخدام الأخلاقي والمرخص فقط — JS Secret Hunter v4",
                  "    🌳 = مكتشف بالـ AST  |  🌟 = Entropy ≥ 4.5  |  🚨 = Open Bucket",
                  "="*74]
        with open(path,"w",encoding="utf-8") as fh:
            fh.write("\n".join(lines))

# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    App().mainloop()

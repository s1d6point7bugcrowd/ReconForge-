#!/bin/bash

# ReconForge Framework - End-to-End Setup Script (v42 - User-Agent Rotation Edition)
# This self-contained script creates a fully operational, AI-enhanced recon framework.
# Must be run with sudo privileges.

#--- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "\n${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
fatal() { echo -e "${RED}[!]${NC} $1" >&2; exit 1; }

#--- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then
  fatal "This script must be run as root. Please use 'sudo ./setup_reconforge.sh'"
fi

#--- Kali Version Check ---
if [ -f /etc/os-release ]; then
    KALI_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    if [[ ! "$KALI_VERSION" =~ ^202[4-5]\..*$ ]]; then
        warn "This script is tested on Kali Linux 2024.x/2025.x. Your version: $KALI_VERSION. It may still work."
    fi
else
    warn "Could not determine Kali Linux version."
fi

#--- Configuration ---
KALI_USER="${KALI_USER:-kali}"
if ! id "$KALI_USER" &>/dev/null; then fatal "User '${KALI_USER}' does not exist."; fi
log "Using non-root user: ${KALI_USER}"

PROJECT_DIR="/opt/reconforge"
PYTHON_VENV_DIR="$PROJECT_DIR/venv"
DB_NAME="reconforge_db"
DB_USER="recon_user"
DB_PASS=$(openssl rand -base64 16)
ADMIN_PASS=$(openssl rand -base64 12)

# Set SecLists path from user's saved preference
SECLISTS_PATH="/home/${KALI_USER}/SecLists"
if [ ! -d "$SECLISTS_PATH" ]; then
    warn "Your preferred SecLists path ('/home/${KALI_USER}/SecLists') not found. Trying the default Kali path."
    SECLISTS_PATH="/usr/share/seclists"
    if [ ! -d "$SECLISTS_PATH" ]; then
        warn "Default SecLists path also not found. FFUF scans will be disabled."
        SECLISTS_PATH=""
    fi
fi
log "Using SecLists from: ${SECLISTS_PATH}"

info "Please provide your API keys for enhanced discovery and analysis."
read -p "Enter GitHub API Token (optional, for higher rate limits on repo discovery): " GITHUB_TOKEN
read -p "Enter Google Gemini API Key (required for AI-powered analysis): " GEMINI_API_KEY
if [ -z "$GEMINI_API_KEY" ]; then
    warn "Gemini API Key not provided. The AI analysis features will be disabled."
fi

#================================================
# STEP 1: INSTALL DEPENDENCIES
#================================================
log "Starting dependency installation... 📦"
apt-get update -y
apt-get install -y postgresql python3-pip python3-venv nmap git redis-server libpango-1.0-0 libpangoft2-1.0-0 -y || fatal "Failed to install system packages."

log "Installing Go and Go-based tools... 🛠️"
if ! command -v go &>/dev/null; then
    GO_VERSION="1.22.5"
    wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz; rm /tmp/go.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest || warn "Failed to install katana."
go install -v github.com/gitleaks/gitleaks/v8@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/bp0lr/gauplus@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/uro@latest
nuclei -update-templates -silent || warn "Failed to update Nuclei templates."

log "Installing NucleiFuzzer and ParamSpider... 🕵️"
if [ ! -d "/opt/NucleiFuzzer" ]; then
    git clone https://github.com/0xKayala/NucleiFuzzer.git /opt/NucleiFuzzer
    chown -R $KALI_USER:$KALI_USER /opt/NucleiFuzzer
    sudo -u $KALI_USER bash -c "cd /opt/NucleiFuzzer && chmod +x install.sh && ./install.sh"
else
    log "NucleiFuzzer already installed at /opt/NucleiFuzzer."
fi
if [ ! -d "/opt/ParamSpider" ]; then
    git clone https://github.com/0xKayala/ParamSpider.git /opt/ParamSpider
    chown -R $KALI_USER:$KALI_USER /opt/ParamSpider
    sudo -u $KALI_USER bash -c "cd /opt/ParamSpider && python3 -m pip install -r requirements.txt"
else
    log "ParamSpider already installed at /opt/ParamSpider."
fi

#==========================================
# STEP 2: SETUP DATABASE & SERVICES
#==========================================
log "Configuring PostgreSQL and Redis... 💾"
systemctl enable --now redis-server.service
systemctl enable --now postgresql.service
PG_PORT=$(pg_lsclusters | awk '$4 == "online" {print $3}' | head -n 1)
if [ -z "$PG_PORT" ]; then fatal "No online PostgreSQL clusters found."; fi

sudo -u postgres psql -p "$PG_PORT" -v ON_ERROR_STOP=1 <<-EOSQL
DROP DATABASE IF EXISTS ${DB_NAME};
DROP USER IF EXISTS ${DB_USER};
CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
EOSQL
if [ $? -ne 0 ]; then fatal "Failed to create database or user."; fi
log "Database '${DB_NAME}' and user '${DB_USER}' created."

#==========================================
# STEP 3: CREATE PROJECT STRUCTURE AND FILES
#==========================================
log "Creating project directory at ${PROJECT_DIR}... 📁"
mkdir -p "${PROJECT_DIR}"/{templates,logs}
chown -R $KALI_USER:$KALI_USER "$PROJECT_DIR"

#--- Secure Credentials (.env file) ---
log "Creating .env file for secure credential storage..."
cat << EOF > "${PROJECT_DIR}/.env"
RECON_DB_PASS=${DB_PASS}
ADMIN_PASS=${ADMIN_PASS}
GITHUB_TOKEN=${GITHUB_TOKEN}
GEMINI_API_KEY=${GEMINI_API_KEY}
EOF
chmod 600 "${PROJECT_DIR}/.env"
chown $KALI_USER:$KALI_USER "${PROJECT_DIR}/.env"

#--- config.py ---
log "Creating config.py..."
cat << 'EOF' > "${PROJECT_DIR}/config.py"
import os
from dotenv import load_dotenv
load_dotenv()

RATE_LIMIT_PROFILES = {'stealth': 5, 'balanced': 50, 'aggressive': 200}
GLOBAL_RATE_PROFILE = os.getenv("GLOBAL_RATE_PROFILE", "balanced")
SLOW_COOK_ENABLED = os.getenv("SLOW_COOK_ENABLED", "False").lower() in ('true', '1', 't')
GLOBAL_RATE_LIMIT = RATE_LIMIT_PROFILES.get(GLOBAL_RATE_PROFILE, 50)

# List of real-world user agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/126.0.2592.81",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.121 Mobile Safari/537.36"
]

CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
DB_CONFIG = {"dbname": "reconforge_db", "user": "recon_user", "password": os.getenv("RECON_DB_PASS"), "host": "localhost", "port": os.getenv("PG_PORT", 5432)}
LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'orchestrator.log')
FFUF_CONFIG = { "wordlist": os.getenv("SECLISTS_PATH", "") }
NUCLEIFUZZER_CONFIG = { "output_folder": "/opt/reconforge/nucleifuzzer_output" }
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
EOF

#--- database.py ---
log "Creating database.py..."
cat << 'EOF' > "${PROJECT_DIR}/database.py"
import psycopg2
from psycopg2.extras import DictCursor, execute_batch
from contextlib import contextmanager
from config import DB_CONFIG

@contextmanager
def get_db_connection():
    conn = psycopg2.connect(**DB_CONFIG); yield conn; conn.close()

def setup_database():
    table_commands = (
        "CREATE TABLE IF NOT EXISTS targets (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, repo_url TEXT);",
        "CREATE TABLE IF NOT EXISTS scans (id SERIAL PRIMARY KEY, target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE, task_id TEXT NOT NULL, start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
        "CREATE TABLE IF NOT EXISTS subdomains (id SERIAL PRIMARY KEY, target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE, hostname TEXT NOT NULL, UNIQUE (target_id, hostname));",
        "CREATE TABLE IF NOT EXISTS web_servers (id SERIAL PRIMARY KEY, subdomain_id INTEGER REFERENCES subdomains(id) ON DELETE CASCADE, url TEXT NOT NULL, port INTEGER, scheme TEXT, title TEXT, webserver TEXT, content_type TEXT, status_code INTEGER, tech TEXT[], UNIQUE (subdomain_id, url));",
        "CREATE TABLE IF NOT EXISTS vulnerabilities (id SERIAL PRIMARY KEY, web_server_id INTEGER REFERENCES web_servers(id) ON DELETE CASCADE, name TEXT NOT NULL, severity TEXT, host TEXT, template_id TEXT, UNIQUE(web_server_id, template_id));",
        "CREATE TABLE IF NOT EXISTS secrets (id SERIAL PRIMARY KEY, target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE, finding TEXT NOT NULL, context TEXT, rule TEXT, UNIQUE(target_id, finding));",
        "CREATE TABLE IF NOT EXISTS ffuf_findings (id SERIAL PRIMARY KEY, web_server_id INTEGER REFERENCES web_servers(id) ON DELETE CASCADE, path TEXT NOT NULL, status_code INTEGER, UNIQUE(web_server_id, path));",
        "CREATE TABLE IF NOT EXISTS nucleifuzzer_findings (id SERIAL PRIMARY KEY, web_server_id INTEGER REFERENCES web_servers(id) ON DELETE CASCADE, vuln_type TEXT NOT NULL, url TEXT NOT NULL, description TEXT, UNIQUE(web_server_id, url, vuln_type));",
        "CREATE TABLE IF NOT EXISTS js_findings (id SERIAL PRIMARY KEY, web_server_id INTEGER REFERENCES web_servers(id) ON DELETE CASCADE, url TEXT NOT NULL, finding_type TEXT NOT NULL, finding_value TEXT NOT NULL, context TEXT, UNIQUE(web_server_id, url, finding_value));",
        "CREATE TABLE IF NOT EXISTS scan_errors (id SERIAL PRIMARY KEY, web_server_id INTEGER REFERENCES web_servers(id) ON DELETE CASCADE, source_tool TEXT, error_message TEXT, UNIQUE(web_server_id, source_tool, error_message));",
        """CREATE TABLE IF NOT EXISTS gemini_analysis (
            id SERIAL PRIMARY KEY,
            vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
            secret_id INTEGER REFERENCES secrets(id) ON DELETE CASCADE,
            js_finding_id INTEGER REFERENCES js_findings(id) ON DELETE CASCADE,
            analysis_text TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_at_least_one_finding CHECK (
                vulnerability_id IS NOT NULL OR secret_id IS NOT NULL OR js_finding_id IS NOT NULL
            )
        );"""
    )

    index_commands = (
        "CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans (target_id);",
        "CREATE INDEX IF NOT EXISTS idx_subdomains_target_id ON subdomains (target_id);",
        "CREATE INDEX IF NOT EXISTS idx_web_servers_subdomain_id ON web_servers (subdomain_id);",
        "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_web_server_id ON vulnerabilities (web_server_id);",
        "CREATE INDEX IF NOT EXISTS idx_secrets_target_id ON secrets (target_id);",
        "CREATE INDEX IF NOT EXISTS idx_ffuf_findings_web_server_id ON ffuf_findings (web_server_id);",
        "CREATE INDEX IF NOT EXISTS idx_nucleifuzzer_findings_web_server_id ON nucleifuzzer_findings (web_server_id);",
        "CREATE INDEX IF NOT EXISTS idx_js_findings_web_server_id ON js_findings (web_server_id);",
        "CREATE INDEX IF NOT EXISTS idx_gemini_analysis_vulnerability_id ON gemini_analysis (vulnerability_id);",
        "CREATE INDEX IF NOT EXISTS idx_gemini_analysis_secret_id ON gemini_analysis (secret_id);",
        "CREATE INDEX IF NOT EXISTS idx_gemini_analysis_js_finding_id ON gemini_analysis (js_finding_id);"
    )

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            for command in table_commands:
                cur.execute(command)
            for command in index_commands:
                cur.execute(command)
            conn.commit()

def add_scan_error(web_server_id, source_tool, error_message):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO scan_errors (web_server_id, source_tool, error_message) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING;", (web_server_id, source_tool, error_message)); conn.commit()

def add_target(name, repo_url=None):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO targets (name, repo_url) VALUES (%s, %s) ON CONFLICT (name) DO UPDATE SET repo_url = EXCLUDED.repo_url RETURNING id;", (name, repo_url)); res=cur.fetchone(); conn.commit(); return res[0] if res else None

def add_scan(target_id, task_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO scans (target_id, task_id) VALUES (%s, %s);", (target_id, task_id)); conn.commit()

def add_subdomains(target_id, subdomains):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            execute_batch(cur, "INSERT INTO subdomains (target_id, hostname) VALUES (%s, %s) ON CONFLICT DO NOTHING;", [(target_id, s) for s in subdomains]); conn.commit()

def add_web_server(subdomain_id, data):
     with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO web_servers (subdomain_id, url, port, scheme, title, webserver, content_type, status_code, tech) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (url) DO NOTHING RETURNING id;", (subdomain_id, data.get('url'), data.get('port'), data.get('scheme'), data.get('title'), data.get('webserver'), data.get('content-type'), data.get('status-code'), data.get('tech', []))); res=cur.fetchone(); conn.commit(); return res[0] if res else None

def add_vulnerability(web_server_id, data):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO vulnerabilities (web_server_id, name, severity, host, template_id) VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING id;",(web_server_id, data.get('info', {}).get('name'), data.get('info', {}).get('severity'), data.get('host'), data.get('template-id'))); res=cur.fetchone(); conn.commit(); return res[0] if res else None

def add_ffuf_finding(web_server_id, result):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ffuf_findings (web_server_id, path, status_code) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING;", (web_server_id, result.get('input', {}).get('FUZZ'), result.get('status'))); conn.commit()

def add_nucleifuzzer_finding(web_server_id, result):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO nucleifuzzer_findings (web_server_id, vuln_type, url, description) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING;",(web_server_id, result.get('type'), result.get('matched-at'), result.get('info', {}).get('description', ''))); conn.commit()

def add_secret(target_id, finding):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO secrets (target_id, finding, context, rule) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING id;", (target_id, finding.get('Secret'), finding.get('Match'), finding.get('RuleID'))); res=cur.fetchone(); conn.commit(); return res[0] if res else None

def add_js_finding(web_server_id, url, finding_type, finding_value, context=None):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO js_findings (web_server_id, url, finding_type, finding_value, context) VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING id;", (web_server_id, url, finding_type, finding_value, context)); res=cur.fetchone(); conn.commit(); return res[0] if res else None

def add_gemini_analysis(text, vuln_id=None, secret_id=None, js_id=None):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO gemini_analysis (analysis_text, vulnerability_id, secret_id, js_finding_id) VALUES (%s, %s, %s, %s);", (text, vuln_id, secret_id, js_id)); conn.commit()

def get_target_by_id(target_id):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("SELECT * FROM targets WHERE id = %s;", (target_id,)); return cur.fetchone()

def get_all_subdomains_for_target(target_id):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("SELECT id, hostname FROM subdomains WHERE target_id = %s;", (target_id,)); return cur.fetchall()

def get_all_web_servers_for_target(target_id):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("SELECT ws.id, ws.url FROM web_servers ws JOIN subdomains s ON ws.subdomain_id = s.id WHERE s.target_id = %s;", (target_id,)); return cur.fetchall()

def get_all_targets_with_stats():
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("""
                SELECT t.id, t.name, t.repo_url,
                       (SELECT task_id FROM scans WHERE target_id = t.id ORDER BY start_time DESC LIMIT 1) as task_id,
                       COUNT(DISTINCT s.id) as subdomain_count,
                       COUNT(DISTINCT v.id) as vulnerability_count,
                       COUNT(DISTINCT f.id) as ffuf_count,
                       COUNT(DISTINCT nf.id) as nucleifuzzer_count,
                       COUNT(DISTINCT sec.id) as secret_count
                FROM targets t
                LEFT JOIN subdomains s ON t.id = s.target_id
                LEFT JOIN web_servers ws ON s.id = ws.subdomain_id
                LEFT JOIN vulnerabilities v ON ws.id = v.web_server_id
                LEFT JOIN ffuf_findings f ON ws.id = f.web_server_id
                LEFT JOIN nucleifuzzer_findings nf ON ws.id = nf.web_server_id
                LEFT JOIN secrets sec ON t.id = sec.target_id
                GROUP BY t.id, t.name, t.repo_url ORDER BY t.name;
            """); return cur.fetchall()

def get_target_details(target_id):
    details = {}
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("SELECT * FROM targets WHERE id = %s;", (target_id,)); details['target'] = cur.fetchone()
            if not details['target']: return None
            cur.execute("SELECT hostname FROM subdomains WHERE target_id = %s ORDER BY hostname;", (target_id,)); details['subdomains'] = cur.fetchall()
            cur.execute("""
                SELECT v.id, v.name, v.severity, v.host, ga.analysis_text
                FROM vulnerabilities v
                JOIN web_servers ws ON v.web_server_id = ws.id
                JOIN subdomains s ON ws.subdomain_id = s.id
                LEFT JOIN gemini_analysis ga ON v.id = ga.vulnerability_id
                WHERE s.target_id = %s ORDER BY severity;
            """, (target_id,)); details['vulnerabilities'] = cur.fetchall()
            cur.execute("SELECT path, status_code FROM ffuf_findings ff JOIN web_servers ws ON ff.web_server_id = ws.id JOIN subdomains s ON ws.subdomain_id = s.id WHERE s.target_id = %s ORDER BY path;", (target_id,)); details['ffuf_findings'] = cur.fetchall()
            cur.execute("SELECT vuln_type, url, description FROM nucleifuzzer_findings nf JOIN web_servers ws ON nf.web_server_id = ws.id JOIN subdomains s ON ws.subdomain_id = s.id WHERE s.target_id = %s ORDER BY vuln_type;", (target_id,)); details['nucleifuzzer_findings'] = cur.fetchall()
            cur.execute("""
                SELECT s.id, s.finding, s.rule, ga.analysis_text
                FROM secrets s
                LEFT JOIN gemini_analysis ga ON s.id = ga.secret_id
                WHERE s.target_id = %s ORDER BY rule;
            """, (target_id,)); details['secrets'] = cur.fetchall()
            cur.execute("""
                SELECT jf.id, jf.url, jf.finding_type, jf.finding_value, jf.context, ga.analysis_text
                FROM js_findings jf 
                JOIN web_servers ws ON jf.web_server_id = ws.id 
                JOIN subdomains s ON ws.subdomain_id = s.id 
                LEFT JOIN gemini_analysis ga ON jf.id = ga.js_finding_id
                WHERE s.target_id = %s ORDER BY jf.url, jf.finding_type;
            """, (target_id,)); details['js_findings'] = cur.fetchall()
            cur.execute("""
                SELECT se.source_tool, se.error_message 
                FROM scan_errors se JOIN web_servers ws ON se.web_server_id = ws.id JOIN subdomains s ON ws.subdomain_id = s.id WHERE s.target_id = %s;
            """, (target_id,)); details['scan_errors'] = cur.fetchall()
    return details
EOF

#--- tasks.py ---
log "Creating tasks.py..."
cat << 'EOF' > "${PROJECT_DIR}/tasks.py"
from celery import Celery, chain, group
from celery.utils.log import get_task_logger
import subprocess, tempfile, os, json, importlib, requests, re, time, random
from urllib.parse import urljoin
import database, config

# Attempt to import Gemini, but don't fail if it's not there
try:
    import google.generativeai as genai
except ImportError:
    genai = None

logger = get_task_logger(__name__)
celery = Celery('tasks', broker=config.CELERY_BROKER_URL, backend=config.CELERY_RESULT_BACKEND)
celery.conf.update(task_track_started=True)

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

def get_rate_limit():
    importlib.reload(config)
    return 5 if config.SLOW_COOK_ENABLED else config.GLOBAL_RATE_LIMIT

def get_random_user_agent():
    return random.choice(config.USER_AGENTS) if config.USER_AGENTS else DEFAULT_UA

@celery.task
def analyze_finding_with_gemini(finding_id, finding_type, finding_data):
    if not genai or not config.GEMINI_API_KEY:
        logger.info("Gemini libraries or API key not available. Skipping AI analysis.")
        return

    logger.info(f"Starting Gemini analysis for {finding_type} ID: {finding_id}")
    genai.configure(api_key=config.GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-pro')

    prompt_templates = {
        "vulnerability": """You are a senior penetration tester analyzing a security finding. Based on the Nuclei scan output below, provide a detailed analysis. Your response must include four sections, each with a markdown header:
1.  ### Vulnerability Explanation: Describe the vulnerability in clear terms.
2.  ### Business Impact: Explain the potential risk to the business if this is exploited.
3.  ### Remediation Steps: Provide a clear, step-by-step guide for a developer to fix the issue.
4.  ### PoC (Proof of Concept): Provide a single, simple `curl` command that demonstrates the issue. Use placeholders like `TARGET_URL` if necessary.

Here is the data:""",
        "secret": """You are a secret detection analyst. A leaked secret was found in a git repository. Based on the finding data below, provide a detailed analysis. Your response must include three sections, each with a markdown header:
1.  ### Secret Analysis: Describe what type of secret this appears to be and the likely service it belongs to.
2.  ### Immediate Risk: Explain the immediate risk and what an attacker could do with this secret.
3.  ### Remediation Protocol: Provide a step-by-step guide on how to revoke the secret, remove it from history, and replace it.

Here is the data:""",
        "js_finding": """You are a JavaScript security analyst. A potentially sensitive item was found in a JavaScript file. Based on the data below, provide a detailed analysis. Your response must include four sections, each with a markdown header:
1.  ### Finding Analysis: Describe what this piece of data represents (e.g., API endpoint, key, PII).
2.  ### Potential Impact: Explain how an attacker could abuse this information.
3.  ### Mitigation Advice: Recommend how to fix this issue (e.g., remove from client-side code, use environment variables).
4.  ### PoC (Proof of Concept): If applicable, provide a `curl` command to demonstrate how an attacker might query the discovered endpoint or use the found value.

Here is the data:"""
    }
    
    prompt = f"{prompt_templates.get(finding_type, 'Analyze the following security finding:')}\n\n```json\n{json.dumps(finding_data, indent=2)}\n```"

    try:
        response = model.generate_content(prompt, request_options={'timeout': 120})
        analysis_text = response.text
        if finding_type == "vulnerability":
            database.add_gemini_analysis(analysis_text, vuln_id=finding_id)
        elif finding_type == "secret":
            database.add_gemini_analysis(analysis_text, secret_id=finding_id)
        elif finding_type == "js_finding":
            database.add_gemini_analysis(analysis_text, js_id=finding_id)
        logger.info(f"Successfully stored Gemini analysis for {finding_type} ID: {finding_id}")
    except Exception as e:
        logger.error(f"Gemini analysis failed for {finding_type} ID {finding_id}: {e}")

@celery.task(bind=True, max_retries=3, default_retry_delay=30)
def run_subfinder(self, target_id, domain):
    logger.info(f"TASK: Starting subfinder for {domain}"); try:
        with tempfile.NamedTemporaryFile(mode='w+') as out_file:
            subprocess.run(['subfinder', '-d', domain, '-o', out_file.name], check=True, capture_output=True)
            out_file.seek(0); subdomains = [line.strip() for line in out_file if line.strip()]; database.add_subdomains(target_id, subdomains)
        return target_id
    except Exception as exc: logger.error(f"Subfinder failed for {domain}: {exc}"); self.retry(exc=exc)

@celery.task(bind=True, max_retries=3, default_retry_delay=30)
def run_httpx(self, target_id):
    logger.info(f"TASK: Starting httpx for target {target_id}"); try:
        subdomains = database.get_all_subdomains_for_target(target_id)
        if not subdomains: return target_id
        with tempfile.NamedTemporaryFile(mode='w+') as in_file, tempfile.NamedTemporaryFile(mode='w+') as out_file:
            in_file.write('\n'.join(s['hostname'] for s in subdomains)); in_file.flush()
            ua_header = f'User-Agent: {get_random_user_agent()}'
            cmd = ['httpx', '-l', in_file.name, '-o', out_file.name, '-json', '-rate-limit', str(get_rate_limit()), '-H', ua_header]
            subprocess.run(cmd, check=True, capture_output=True)
            out_file.seek(0); subdomain_map = {s['hostname']: s['id'] for s in subdomains}
            for line in out_file:
                if line.strip(): data = json.loads(line); hostname = data.get('host', '').split(':')[0]
                if hostname in subdomain_map: database.add_web_server(subdomain_map[hostname], data)
        return target_id
    except Exception as exc: logger.error(f"Httpx failed for target {target_id}: {exc}"); self.retry(exc=exc)

@celery.task(bind=True, max_retries=2, default_retry_delay=60)
def run_nuclei_on_server(self, server, progress_info):
    logger.info(f"TASK: Starting nuclei for {server['url']}"); try:
        with tempfile.NamedTemporaryFile(mode='w+') as out_file:
            ua_header = f'User-Agent: {get_random_user_agent()}'
            cmd = ['nuclei', '-u', server['url'], '-jsonl', '-o', out_file.name, '-rl', str(get_rate_limit()), '-H', ua_header]
            subprocess.run(cmd, check=True, capture_output=True)
            out_file.seek(0)
            for line in out_file:
                if line.strip(): data = json.loads(line); vuln_id = database.add_vulnerability(server['id'], data)
                if vuln_id: analyze_finding_with_gemini.delay(vuln_id, "vulnerability", data)
        progress_info['completed'] += 1; self.update_state(state='PROGRESS', meta=progress_info)
    except Exception as exc: logger.error(f"Nuclei failed for {server['url']}: {exc}"); self.retry(exc=exc)

@celery.task(bind=True, max_retries=2, default_retry_delay=60)
def run_ffuf_on_server(self, server, progress_info):
    logger.info(f"TASK: Starting ffuf for {server['url']}"); try:
        if not config.FFUF_CONFIG.get('wordlist'): return
        with tempfile.NamedTemporaryFile(mode='w+') as out_file:
            ua_header = f'User-Agent: {get_random_user_agent()}'
            cmd = ['ffuf', '-u', f"{server['url']}/FUZZ", '-w', config.FFUF_CONFIG['wordlist'], '-o', out_file.name, '-of', 'json', '-r', str(get_rate_limit()), '-H', ua_header]
            subprocess.run(cmd, check=True, capture_output=True)
            out_file.seek(0); results = json.load(out_file).get('results', [])
            for result in results: database.add_ffuf_finding(server['id'], result)
        progress_info['completed'] += 1; self.update_state(state='PROGRESS', meta=progress_info)
    except Exception as exc: logger.error(f"Ffuf failed for {server['url']}: {exc}"); self.retry(exc=exc)

@celery.task(bind=True, max_retries=2, default_retry_delay=60)
def run_nucleifuzzer(self, target_id, domain, progress_info):
    logger.info(f"TASK: Starting NucleiFuzzer for {domain}"); try:
        output_dir = config.NUCLEIFUZZER_CONFIG['output_folder']; os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{domain.replace('.', '_')}_nuclei_results.txt")
        subprocess.run(['nf', '-d', domain, '-o', output_dir, '-r', str(get_rate_limit())], check=True, capture_output=True)
        web_servers = database.get_all_web_servers_for_target(target_id); web_server_urls = {ws['url']: ws['id'] for ws in web_servers}
        with open(output_file, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        result = json.loads(line); url = result.get('matched-at', '')
                        web_server_id = next((ws_id for ws_url, ws_id in web_server_urls.items() if url.startswith(ws_url)), None)
                        if web_server_id: database.add_nucleifuzzer_finding(web_server_id, result)
                    except json.JSONDecodeError: continue
        progress_info['completed'] += 1; self.update_state(state='PROGRESS', meta=progress_info)
    except Exception as exc:
        logger.error(f"NucleiFuzzer failed for {domain}: {exc}"); database.add_scan_error(None, 'NucleiFuzzer', f"Failed to scan {domain}: {exc}"); self.retry(exc=exc)

@celery.task(bind=True, max_retries=2, default_retry_delay=60)
def run_secrets_scan(self, target_id, progress_info):
    logger.info(f"TASK: Starting secrets scan for target {target_id}"); try:
        target = database.get_target_by_id(target_id); repo_url = target.get('repo_url')
        if not repo_url:
            domain = target['name'].split('.')[0]; logger.info(f"No repo URL for {domain}. Attempting discovery...");
            headers = {'Authorization': f'token {config.GITHUB_TOKEN}'} if config.GITHUB_TOKEN else {};
            try:
                response = requests.get(f"https://api.github.com/search/repositories?q=org:{domain}", headers=headers, timeout=10)
                if response.ok and response.json().get('items'): repo_url = response.json()['items'][0]['html_url']; logger.info(f"Discovered repo for {domain}: {repo_url}")
                else: logger.warning(f"Could not discover a repository for {domain}. Skipping secrets scan."); progress_info['completed'] += 1; self.update_state(state='PROGRESS', meta=progress_info); return
            except requests.RequestException as e: logger.error(f"GitHub API request failed: {e}"); progress_info['completed'] += 1; self.update_state(state='PROGRESS', meta=progress_info); return
        with tempfile.NamedTemporaryFile(mode='w+') as out_file:
            cmd = ['gitleaks', 'detect', '--source', repo_url, '--report-path', out_file.name, '--report-format', 'json', '--no-git']
            if config.GITHUB_TOKEN: cmd.extend(['--github-token', config.GITHUB_TOKEN])
            subprocess.run(cmd, check=True, capture_output=True); out_file.seek(0); findings = json.load(out_file)
            for finding in findings: secret_id = database.add_secret(target_id, finding)
            if secret_id: analyze_finding_with_gemini.delay(secret_id, "secret", finding)
        progress_info['completed'] += 1; self.update_state(state='PROGRESS', meta=progress_info)
    except Exception as exc: logger.error(f"Secrets scan failed for target {target_id}: {exc}"); self.retry(exc=exc)

@celery.task(bind=True, max_retries=2, default_retry_delay=60)
def run_js_scan(self, server, progress_info):
    logger.info(f"TASK: Starting JS scan for {server['url']}"); try:
        js_urls = set()
        with tempfile.NamedTemporaryFile(mode='w+') as out_file:
            katana_ua_header = f'User-Agent: {get_random_user_agent()}'
            cmd = ['katana', '-u', server['url'], '-silent', '-jc', '-o', out_file.name, '-H', katana_ua_header]
            subprocess.run(cmd, check=True, capture_output=True, text=True); out_file.seek(0)
            for line in out_file:
                if line.strip().endswith('.js'): js_urls.add(urljoin(server['url'], line.strip()))
        patterns = {'api_key': r'["\'](?!AKIA)[A-Za-z0-9_\\-]{32,45}["\']', 'url_endpoint': r'["\'](https?:\/\/[^\s"\'<>]+)["\']', 'email': r'["\']([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']', 'aws_key': r'(AKIA[0-9A-Z]{16})', 'jwt_token': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', 'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 'secret_key': r'["\']secret[_-]?key["\']\s*[:=]\s*["\'][A-Za-z0-9+/=._-]{20,}["\']', 'google_api_key': r'(AIza[0-9A-Za-z\\-_]{35})', 'firebase_url': r'([a-z0-9-]+\.firebaseio\.com)', 'stripe_api_key': r'((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24})', 'generic_password': r'(?i)(password|pass|pwd|credential)s?\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'commented_out_code': r'(?://|/\*)\s*([\'"`/][a-zA-Z0-9_/.\-]{10,}[\'"`])'}
        for js_url in js_urls:
            try:
                time.sleep(0.2); response = requests.get(js_url, timeout=10, verify=False, headers={'User-Agent': get_random_user_agent()})
                if response.status_code == 200 and 'javascript' in response.headers.get('Content-Type', ''):
                    content = response.text
                    for f_type, pattern in patterns.items():
                        for match in re.finditer(pattern, content):
                            value = match.group(1) if match.groups() else match.group(0); context_start = max(0, match.start() - 50); context_end = min(len(content), match.end() + 50); context = content[context_start:context_end]
                            js_finding_id = database.add_js_finding(server['id'], js_url, f_type, value, context)
                            if js_finding_id: analyze_finding_with_gemini.delay(js_finding_id, "js_finding", {'url': js_url, 'type': f_type, 'value': value, 'context': context})
            except requests.RequestException as e:
                logger.warning(f"Could not fetch JS file {js_url}: {e}"); database.add_scan_error(server['id'], 'JS Scan', f"Failed to fetch {js_url}: {e}")
        progress_info['completed'] += 1; self.update_state(state='PROGRESS', meta=progress_info)
    except Exception as exc: logger.error(f"JS scan failed for {server['url']}: {exc}"); self.retry(exc=exc)

@celery.task
def run_post_discovery_scans(target_id):
    web_servers = database.get_all_web_servers_for_target(target_id)
    if not web_servers: return
    total_tasks = len(web_servers) * 3 + 2; progress_info = {'completed': 0, 'total': total_tasks}
    celery.current_task.update_state(state='PROGRESS', meta=progress_info)
    scan_tasks = [run_nuclei_on_server.s(s, progress_info) for s in web_servers]
    scan_tasks.extend([run_ffuf_on_server.s(s, progress_info) for s in web_servers])
    scan_tasks.extend([run_js_scan.s(s, progress_info) for s in web_servers])
    scan_tasks.append(run_secrets_scan.s(target_id, progress_info))
    scan_tasks.append(run_nucleifuzzer.s(target_id, database.get_target_by_id(target_id)['name'], progress_info))
    group(scan_tasks).apply_async()

def start_scan_chain(target_id, domain):
    result = chain(run_subfinder.s(target_id, domain), run_httpx.s(), run_post_discovery_scans.s()).apply_async()
    database.add_scan(target_id, result.id); return result.id
EOF

#--- app.py ---
log "Creating app.py..."
cat << 'EOF' > "${PROJECT_DIR}/app.py"
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Regexp, Optional
import os, importlib, database, tasks, config
from celery.result import AsyncResult
from flask_httpauth import HTTPBasicAuth
from weasyprint import HTML
import markdown

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
csrf = CSRFProtect(app)
auth = HTTPBasicAuth()
users = {"admin": os.getenv("ADMIN_PASS", "admin")}

@app.template_filter('markdown')
def markdown_filter(text):
    return markdown.markdown(text or "", extensions=['fenced_code', 'tables'])

@auth.verify_password
def verify_password(username, password):
    if username in users and users.get(username) == password: return username

with app.app_context(): database.setup_database()

class TargetForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')])
    repo_url = StringField('Repo URL', validators=[Optional(), Regexp(r'^https?://.*')])
    submit = SubmitField('Add/Update Target')

class ConfigForm(FlaskForm):
    rate_profile = SelectField('Rate Limit Profile', choices=[(p, p.title()) for p in config.RATE_LIMIT_PROFILES.keys()])
    slow_cook = BooleanField('Override: Slow Cook (5 req/s)')
    submit = SubmitField('Update Config')

@app.route('/', methods=['GET', 'POST'])
@auth.login_required
def dashboard():
    form = TargetForm()
    if form.validate_on_submit():
        database.add_target(form.domain.data, form.repo_url.data); flash(f"Target {form.domain.data} added/updated.", 'success'); return redirect(url_for('dashboard'))
    elif request.method == 'POST' and 'scan_target_id' in request.form:
        target_id, domain = request.form.get('scan_target_id'), request.form.get('scan_domain')
        task_id = tasks.start_scan_chain(int(target_id), domain); flash(f"Scan initiated for {domain} (Task ID: {task_id})", 'info'); return redirect(url_for('dashboard'))
    targets = database.get_all_targets_with_stats(); return render_template('dashboard.html', targets=targets, form=form, title="Dashboard")

@app.route('/status/<task_id>')
@auth.login_required
def task_status(task_id):
    task = AsyncResult(task_id, app=tasks.celery); info = task.info if isinstance(task.info, dict) else str(task.info); progress_str = "N/A"
    if task.state == 'PROGRESS' and isinstance(info, dict): progress_str = f"{info.get('completed',0)}/{info.get('total',0)}"
    elif task.state == 'FAILURE': info = str(task.info)
    return jsonify({'state': task.state, 'progress': progress_str, 'info': info})

@app.route('/cancel/<task_id>', methods=['POST'])
@auth.login_required
def cancel_task(task_id):
    tasks.celery.control.revoke(task_id, terminate=True); flash(f"Scan cancellation request sent for Task ID: {task_id}", 'warning'); return redirect(url_for('dashboard'))

@app.route('/config', methods=['GET', 'POST'])
@auth.login_required
def configure():
    form = ConfigForm()
    if form.validate_on_submit():
        # This is a simplified way to update .env; a more robust method is recommended for production
        with open('.env', 'r') as file: lines = file.readlines()
        with open('.env', 'w') as file:
            for line in lines:
                if line.startswith('GLOBAL_RATE_PROFILE='): file.write(f'GLOBAL_RATE_PROFILE={form.rate_profile.data}\n')
                elif line.startswith('SLOW_COOK_ENABLED='): file.write(f'SLOW_COOK_ENABLED={form.slow_cook.data}\n')
                else: file.write(line)
        importlib.reload(config); flash('Configuration updated successfully.', 'success'); return redirect(url_for('configure'))
    form.rate_profile.data = config.GLOBAL_RATE_PROFILE; form.slow_cook.data = config.SLOW_COOK_ENABLED
    return render_template('config.html', form=form, title="Configuration")

@app.route('/target/<int:target_id>')
@auth.login_required
def target_details(target_id):
    details = database.get_target_details(target_id)
    if not details: flash('Target not found.', 'danger'); return redirect(url_for('dashboard'))
    return render_template('target_details.html', details=details, title=f"Details for {details['target']['name']}")

@app.route('/logs')
@auth.login_required
def view_logs():
    page = request.args.get('page', 1, type=int); per_page = 200
    try:
        with open(config.LOG_FILE, 'r') as f: log_lines = f.readlines()
        total_lines = len(log_lines); start = (page - 1) * per_page; end = start + per_page
        paginated_logs = log_lines[start:end]; total_pages = (total_lines + per_page - 1) // per_page
    except FileNotFoundError: paginated_logs = ["Log file not found."]; total_pages = 0
    return render_template('logs.html', logs=paginated_logs, page=page, total_pages=total_pages, title="Logs")

@app.route('/report/<int:target_id>')
@auth.login_required
def generate_report(target_id):
    details = database.get_target_details(target_id)
    if not details: flash('Target not found.', 'danger'); return redirect(url_for('dashboard'))
    html_report = render_template('report.html', details=details)
    pdf = HTML(string=html_report).write_pdf()
    response = make_response(pdf); response.headers['Content-Type'] = 'application/pdf'; response.headers['Content-Disposition'] = f'attachment; filename=ReconForge_Report_{details["target"]["name"]}.pdf'
    return response

@app.route('/cleanup', methods=['POST'])
@auth.login_required
def cleanup():
    try:
        with database.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scans WHERE start_time < CURRENT_TIMESTAMP - INTERVAL '7 days';")
                conn.commit()
        flash('Old scan data (older than 7 days) has been cleaned up.', 'success')
    except Exception as e: flash(f'An error occurred during cleanup: {e}', 'danger')
    return redirect(url_for('dashboard'))
EOF

#--- templates/base.html ---
log "Creating base.html template..."
cat << 'EOF' > "${PROJECT_DIR}/templates/base.html"
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{{ title }} - ReconForge</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"><style>body{background-color:#f8f9fa}.sidebar{position:fixed;top:0;left:0;bottom:0;width:280px;padding:20px;background-color:#343a40;color:#fff}.sidebar h2{font-weight:bold}.sidebar .nav-link{color:#adb5bd;font-size:1.1rem;margin-bottom:10px}.sidebar .nav-link.active,.sidebar .nav-link:hover{color:#fff}.main-content{margin-left:280px;padding:20px}.card-header{font-weight:bold}details summary{cursor:pointer;font-weight:bold;color:#0d6efd}.ai-analysis{background-color:#eef7ff;border-left:4px solid #0d6efd;padding:15px;margin-top:10px;border-radius:4px}.ai-analysis pre{background-color:#282c34;color:#abb2bf;padding:1em;border-radius:5px;white-space:pre-wrap;word-wrap:break-word}</style></head><body><div class="sidebar"><a href="/" class="d-flex align-items-center mb-4 text-white text-decoration-none"><h2><i class="bi bi-shield-shaded"></i> ReconForge</h2></a><hr><ul class="nav nav-pills flex-column mb-auto"><li class="nav-item"><a href="{{ url_for('dashboard') }}" class="nav-link {% if request.endpoint == 'dashboard' %}active{% endif %}"><i class="bi bi-grid-fill"></i> Dashboard</a></li><li><a href="{{ url_for('configure') }}" class="nav-link {% if request.endpoint == 'configure' %}active{% endif %}"><i class="bi bi-gear-fill"></i> Configuration</a></li><li><a href="{{ url_for('view_logs') }}" class="nav-link {% if request.endpoint == 'view_logs' %}active{% endif %}"><i class="bi bi-journal-text"></i> View Logs</a></li></ul></div><div class="main-content">{% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}<div class="container mt-3">{% for category, message in messages %}<div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">{{ message }}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>{% endfor %}</div>{% endif %}{% endwith %}{% block content %}{% endblock %}</div><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>{% block scripts %}{% endblock %}</body></html>
EOF

#--- templates/dashboard.html ---
log "Creating dashboard.html template..."
cat << 'EOF' > "${PROJECT_DIR}/templates/dashboard.html"
{% extends "base.html" %}{% block content %}<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom"><h1>Dashboard</h1><div class="btn-toolbar mb-2 mb-md-0"><form action="{{ url_for('cleanup') }}" method="POST" class="d-inline"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Are you sure you want to delete scan data older than 7 days?')"><i class="bi bi-trash"></i> Cleanup Old Scans</button></form></div></div><div class="card mb-4"><div class="card-header">Add or Update Target</div><div class="card-body"><form method="POST" action="">{{ form.hidden_tag() }}<div class="row"><div class="col-md-6 mb-3">{{ form.domain.label(class="form-label") }}{{ form.domain(class="form-control") }}</div><div class="col-md-6 mb-3">{{ form.repo_url.label(class="form-label") }}{{ form.repo_url(class="form-control") }}</div></div>{{ form.submit(class="btn btn-primary") }}</form></div></div><div class="card"><div class="card-header">Targets</div><div class="card-body"><div class="table-responsive"><table class="table table-striped"><thead><tr><th>Target Domain</th><th>Subdomains</th><th>Vulns</th><th>FFUF</th><th>Fuzzer</th><th>Secrets</th><th>Status</th><th>Actions</th></tr></thead><tbody>{% for target in targets %}<tr><td><a href="{{ url_for('target_details', target_id=target.id) }}">{{ target.name }}</a><br><small class="text-muted">{{ target.repo_url }}</small></td><td>{{ target.subdomain_count }}</td><td>{{ target.vulnerability_count }}</td><td>{{ target.ffuf_count }}</td><td>{{ target.nucleifuzzer_count }}</td><td>{{ target.secret_count }}</td><td><div id="status-{{ target.task_id }}">Loading...</div></td><td><div class="btn-group"><form action="" method="POST" class="me-2"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="scan_target_id" value="{{ target.id }}"><input type="hidden" name="scan_domain" value="{{ target.name }}"><button type="submit" class="btn btn-sm btn-success"><i class="bi bi-play-circle"></i> Scan</button></form><form action="{{ url_for('cancel_task', task_id=target.task_id) }}" method="POST"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button type="submit" class="btn btn-sm btn-warning"><i class="bi bi-stop-circle"></i> Cancel</button></form></div></td></tr>{% else %}<tr><td colspan="8" class="text-center">No targets found. Add one above to begin.</td></tr>{% endfor %}</tbody></table></div></div></div>{% endblock %}{% block scripts %}<script>document.addEventListener('DOMContentLoaded', function(){const statuses = document.querySelectorAll('[id^="status-"]');function fetchStatus(element, taskId){fetch(`/status/${taskId}`).then(response=>response.json()).then(data=>{let badgeClass = 'bg-secondary';if(data.state === 'SUCCESS') badgeClass = 'bg-success';else if(data.state === 'PENDING') badgeClass = 'bg-info text-dark';else if(data.state === 'FAILURE') badgeClass = 'bg-danger';else if(data.state === 'PROGRESS') badgeClass = 'bg-primary';element.innerHTML = `<span class="badge ${badgeClass}">${data.state}</span>`;if(data.progress !== 'N/A'){element.innerHTML += ` <span class="badge bg-light text-dark">${data.progress}</span>`;}}).catch(error=>{element.innerHTML = '<span class="badge bg-dark">Error</span>';console.error('Error fetching status:', error);});}statuses.forEach(element=>{const taskId = element.id.split('-')[1];if(taskId && taskId !== 'None'){fetchStatus(element, taskId);setInterval(()=>fetchStatus(element, taskId), 5000);} else {element.innerHTML = '<span class="badge bg-secondary">N/A</span>';}});});</script>{% endblock %}
EOF

#--- templates/config.html ---
log "Creating config.html template..."
cat << 'EOF' > "${PROJECT_DIR}/templates/config.html"
{% extends "base.html" %}{% block content %}<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom"><h1>Configuration</h1></div><div class="card"><div class="card-header">Framework Settings</div><div class="card-body"><form method="POST" action="">{{ form.hidden_tag() }}<div class="mb-3">{{ form.rate_profile.label(class="form-label") }}{{ form.rate_profile(class="form-select") }}<div class="form-text">Stealth (5), Balanced (50), Aggressive (200) requests/second.</div></div><div class="form-check mb-3">{{ form.slow_cook(class="form-check-input") }}{{ form.slow_cook.label(class="form-check-label") }}<div class="form-text">Overrides the profile above and forces a rate limit of 5 req/s for all tools. Useful for sensitive environments.</div></div>{{ form.submit(class="btn btn-primary") }}</form></div></div>{% endblock %}
EOF

#--- templates/logs.html ---
log "Creating logs.html template..."
cat << 'EOF' > "${PROJECT_DIR}/templates/logs.html"
{% extends "base.html" %}{% block content %}<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom"><h1>Orchestrator Logs</h1></div><div class="card"><div class="card-header">Log Viewer</div><div class="card-body"><pre class="bg-dark text-white p-3 rounded" style="max-height: 70vh; overflow-y: auto;"><code>{% for line in logs %}{{ line }}{% endfor %}</code></pre></div><div class="card-footer"><nav><ul class="pagination">{% if page > 1 %}<li class="page-item"><a class="page-link" href="{{ url_for('view_logs', page=page-1) }}">Previous</a></li>{% endif %}{% if page < total_pages %}<li class="page-item"><a class="page-link" href="{{ url_for('view_logs', page=page+1) }}">Next</a></li>{% endif %}</ul></nav></div></div>{% endblock %}
EOF

#--- templates/target_details.html ---
log "Creating target_details.html..."
cat << 'EOF' > "${PROJECT_DIR}/templates/target_details.html"
{% extends "base.html" %}{% block content %}<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom"><h1>Details for <span class="text-primary">{{details.target.name}}</span></h1><a href="{{ url_for('generate_report', target_id=details.target.id) }}" class="btn btn-info"><i class="bi bi-file-earmark-pdf"></i> Download PDF Report</a></div><div class="row"><div class="col-md-12"><div class="card mb-4"><div class="card-header">Vulnerabilities ({{details.vulnerabilities|length}})</div><table class="table mb-0"><thead><tr><th>Name</th><th>Severity</th><th>Host</th></tr></thead><tbody>{% for v in details.vulnerabilities %}<tr class="align-middle"><td>{{v.name}}</td><td><span class="badge bg-{{v.severity.lower() if v.severity in ['critical', 'high', 'medium', 'low'] else 'secondary'}}">{{v.severity|title}}</span></td><td>{{v.host}}</td></tr>{% if v.analysis_text %}<tr><td colspan="3" class="p-0"><div class="ai-analysis m-2"><details><summary><i class="bi bi-robot"></i> Gemini AI Analysis</summary><div class="mt-2">{{ v.analysis_text | markdown | safe }}</div></details></div></td></tr>{% endif %}{% else %}<tr><td colspan="3" class="text-center">No vulnerabilities found.</td></tr>{% endfor %}</tbody></table></div><div class="card mb-4"><div class="card-header">Secrets ({{details.secrets|length}})</div><table class="table mb-0"><thead><tr><th>Rule</th><th>Finding</th></tr></thead><tbody>{% for s in details.secrets %}<tr><td>{{s.rule}}</td><td style="word-break:break-all;">{{s.finding}}</td></tr>{% if s.analysis_text %}<tr><td colspan="2" class="p-0"><div class="ai-analysis m-2"><details><summary><i class="bi bi-robot"></i> Gemini AI Analysis</summary><div class="mt-2">{{ s.analysis_text | markdown | safe }}</div></details></div></td></tr>{% endif %}{% else %}<tr><td colspan="2" class="text-center">No secrets found.</td></tr>{% endfor %}</tbody></table></div><div class="card mb-4"><div class="card-header">JavaScript Findings ({{details.js_findings|length}})</div><div class="m-3"><label for="jsFilter" class="form-label">Filter by Type</label><select id="jsFilter" class="form-select" onchange="filterTable()"><option value="all">All</option><option value="api_key">Api Key</option><option value="url_endpoint">Url Endpoint</option><option value="email">Email</option><option value="aws_key">Aws Key</option><option value="jwt_token">Jwt Token</option><option value="ip_address">Ip Address</option><option value="secret_key">Secret Key</option><option value="google_api_key">Google Api Key</option><option value="firebase_url">Firebase Url</option><option value="stripe_api_key">Stripe Api Key</option><option value="generic_password">Generic Password</option><option value="commented_out_code">Commented Out Code</option></select></div><table class="table mb-0" id="jsFindingsTable"><thead><tr><th>URL</th><th>Type</th><th>Value</th></tr></thead><tbody>{% for j in details.js_findings %}<tr data-finding-type="{{j.finding_type}}"><td>{{j.url}}</td><td>{{j.finding_type|replace('_', ' ')|title}}</td><td style="word-break:break-all;">{{j.finding_value}}</td></tr>{% if j.analysis_text %}<tr><td colspan="3" class="p-0"><div class="ai-analysis m-2"><details><summary><i class="bi bi-robot"></i> Gemini AI Analysis</summary><div class="mt-2">{{ j.analysis_text | markdown | safe }}</div></details></div></td></tr>{% endif %}{% else %}<tr><td colspan="3" class="text-center">No JavaScript findings found.</td></tr>{% endfor %}</tbody></table></div><div class="accordion" id="otherFindingsAccordion"><div class="accordion-item"><h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseSubdomains">Subdomains ({{details.subdomains|length}})</button></h2><div id="collapseSubdomains" class="accordion-collapse collapse"><div class="accordion-body"><ul class="list-group">{% for s in details.subdomains %}<li class="list-group-item">{{s.hostname}}</li>{% else %}<li class="list-group-item">No subdomains found.</li>{% endfor %}</ul></div></div></div><div class="accordion-item"><h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFFUF">FFUF Findings ({{details.ffuf_findings|length}})</button></h2><div id="collapseFFUF" class="accordion-collapse collapse"><div class="accordion-body"><table class="table table-sm"><thead><tr><th>Path</th><th>Status</th></tr></thead><tbody>{% for f in details.ffuf_findings %}<tr><td>{{f.path}}</td><td>{{f.status_code}}</td></tr>{% else %}<tr><td colspan="2">No FFUF findings.</td></tr>{% endfor %}</tbody></table></div></div></div><div class="accordion-item"><h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFuzzer">NucleiFuzzer Findings ({{details.nucleifuzzer_findings|length}})</button></h2><div id="collapseFuzzer" class="accordion-collapse collapse"><div class="accordion-body"><table class="table table-sm"><thead><tr><th>Type</th><th>URL</th></tr></thead><tbody>{% for nf in details.nucleifuzzer_findings %}<tr><td>{{nf.vuln_type}}</td><td>{{nf.url}}</td></tr>{% else %}<tr><td colspan="2">No Fuzzer findings.</td></tr>{% endfor %}</tbody></table></div></div></div><div class="accordion-item"><h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseErrors">Scan Errors ({{details.scan_errors|length}})</button></h2><div id="collapseErrors" class="accordion-collapse collapse"><div class="accordion-body"><table class="table table-danger table-sm"><thead><tr><th>Source</th><th>Message</th></tr></thead><tbody>{% for error in details.scan_errors %}<tr><td>{{error.source_tool}}</td><td>{{error.error_message}}</td></tr>{% else %}<tr><td colspan="2">No errors recorded.</td></tr>{% endfor %}</tbody></table></div></div></div></div></div></div></div>{% endblock %}{% block scripts %} <script>function filterTable(){const t=document.getElementById("jsFilter").value,e=document.getElementById("jsFindingsTable").getElementsByTagName("tr");for(let n=0;n<e.length;n++){const o=e[n];o.dataset.findingType?("all"===t||o.dataset.findingType===t?o.style.display="":o.style.display="none"):null}}</script>{% endblock %}
EOF

#--- templates/report.html ---
log "Creating report.html..."
cat << 'EOF' > "${PROJECT_DIR}/templates/report.html"
<!DOCTYPE html><html><head><title>ReconForge Report</title><style>@page{size:letter;margin:1in}body{font-family:sans-serif;margin:0;font-size:10pt}h1,h2,h3{color:#333;border-bottom:1px solid #eee;padding-bottom:5px}h1{font-size:24pt}h2{font-size:18pt}h3{font-size:14pt;border:none;margin-top:20px}table{border-collapse:collapse;width:100%;margin-top:20px}th,td{border:1px solid #ccc;padding:8px;text-align:left;word-break:break-all}th{background:#f4f4f4}.severity-critical{background-color:#7d0000;color:#fff}.severity-high{background-color:#ff4d4d}.severity-medium{background-color:#ffd633}.severity-low{background-color:#99cc33}.severity-info{background-color:#b3d9ff}.ai-analysis-pdf{background-color:#eef7ff;border:1px solid #d0e8ff;padding:10px;margin:10px 0;page-break-inside:avoid}.ai-analysis-pdf pre{background-color:#f0f0f0;padding:0.5em;border-radius:3px;white-space:pre-wrap;word-wrap:break-word}</style></head><body><h1>ReconForge Report: {{details.target.name}}</h1><h2>Vulnerabilities ({{details.vulnerabilities|length}})</h2><table><thead><tr><th>Name</th><th>Severity</th><th>Host</th></tr></thead><tbody>{% for v in details.vulnerabilities %}<tr class="severity-{{v.severity.lower() if v.severity else 'info'}}"><td>{{v.name}}</td><td>{{v.severity|title}}</td><td>{{v.host}}</td></tr>{% if v.analysis_text %}<tr><td colspan="3"><div class="ai-analysis-pdf">{{ v.analysis_text | markdown | safe }}</div></td></tr>{% endif %}{% else %}<tr><td colspan="3">No vulnerabilities found.</td></tr>{% endfor %}</tbody></table><h2>Secrets Found ({{details.secrets|length}})</h2><table><thead><tr><th>Rule</th><th>Finding</th></tr></thead><tbody>{% for s in details.secrets %}<tr><td>{{s.rule}}</td><td>{{s.finding}}</td></tr>{% if s.analysis_text %}<tr><td colspan="2"><div class="ai-analysis-pdf">{{ s.analysis_text | markdown | safe }}</div></td></tr>{% endif %}{% else %}<tr><td colspan="2">No secrets found.</td></tr>{% endfor %}</tbody></table><h2>JavaScript Findings ({{details.js_findings|length}})</h2><table><thead><tr><th>URL</th><th>Type</th><th>Value</th></tr></thead><tbody>{% for j in details.js_findings %}<tr><td>{{j.url}}</td><td>{{j.finding_type|replace('_', ' ')|title}}</td><td>{{j.finding_value}}</td></tr>{% if j.analysis_text %}<tr><td colspan="3"><div class="ai-analysis-pdf">{{ j.analysis_text | markdown | safe }}</div></td></tr>{% endif %}{% else %}<tr><td colspan="3">No JavaScript findings.</td></tr>{% endfor %}</tbody></table><h2>Subdomains ({{details.subdomains|length}})</h2><table><tr><th>Hostname</th></tr>{% for s in details.subdomains %}<tr><td>{{s.hostname}}</td></tr>{% else %}<tr><td>No subdomains found.</td></tr>{% endfor %}</table></body></html>
EOF

#--- start.sh ---
log "Creating start.sh script..."
cat << EOF > "${PROJECT_DIR}/start.sh"
#!/bin/bash
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
log_file="${PROJECT_DIR}/logs/orchestrator.log"
export PATH=\$PATH:/usr/local/go/bin:/home/${KALI_USER}/go/bin
echo "--- Starting ReconForge Framework ---" | tee -a \$log_file
echo "Worker PATH: \$PATH" | tee -a \$log_file
# Start Celery worker in the background
sudo -u ${KALI_USER} bash -c "cd ${PROJECT_DIR} && . venv/bin/activate && celery -A tasks.celery worker --loglevel=info -P solo" &
CELERY_PID=\$!
echo "Celery worker started with PID: \$CELERY_PID" | tee -a \$log_file
# Start Flask app in the foreground
sudo -u ${KALI_USER} bash -c "cd ${PROJECT_DIR} && . venv/bin/activate && gunicorn --workers 3 --bind 0.0.0.0:5000 app:app"
EOF
chmod +x "${PROJECT_DIR}/start.sh"

#--- stop.sh ---
log "Creating stop.sh script..."
cat << EOF > "${PROJECT_DIR}/stop.sh"
#!/bin/bash
echo "--- Stopping ReconForge Framework ---"
echo "Searching for and stopping Gunicorn, Flask, and Celery processes..."
pkill -f "gunicorn --workers 3"
pkill -f "celery -A tasks.celery worker"
pkill -f "python3 app.py"
sleep 2
if pgrep -f "gunicorn" || pgrep -f "celery -A tasks.celery worker" || pgrep -f "python3 app.py"; then
    echo "Processes still running. Sending SIGKILL..."
    pkill -9 -f "gunicorn"
    pkill -9 -f "celery -A tasks.celery worker"
    pkill -9 -f "python3 app.py"
fi
echo "ReconForge processes stopped."
EOF
chmod +x "${PROJECT_DIR}/stop.sh"

#--- README.md ---
log "Creating README.md..."
cat << EOF > "${PROJECT_DIR}/README.md"
# ReconForge Framework (v42 - User-Agent Rotation Edition)

ReconForge is an automated, AI-enhanced reconnaissance framework for Kali Linux. It provides a web-based dashboard to manage targets and orchestrate a powerful scanning pipeline, designed to discover subdomains, find vulnerabilities, and parse files for sensitive data.

## Features
- **AI-Powered Analysis**: Integrated with Google's Gemini Pro to provide detailed explanations, business impact assessments, remediation advice, and actionable `curl` Proof of Concept commands.
- **Stealth & Evasion**: Rotates through a list of real-world User-Agent strings for all tools to better mimic legitimate traffic.
- **Optimized Database**: Includes indexing on key tables for improved performance on large datasets.
- **Subdomain Enumeration**: \`subfinder\`.
- **Web Server Detection**: \`httpx\`.
- **Vulnerability Scanning**: \`nuclei\` and enhanced fuzzing with \`NucleiFuzzer\`.
- **Content Discovery**: \`ffuf\`.
- **Secrets Scanning**: \`gitleaks\` for git repositories.
- **JavaScript Analysis**: \`katana\` and a comprehensive set of regex patterns.
- **Modern Web Interface**: A clean, responsive dashboard with dynamic status updates, filtering, error reporting, and PDF generation.

## Setup
1.  Run the setup script as root. You will be prompted for your Google Gemini API key.
    \`\`\`bash
    sudo ./setup_reconforge.sh
    \`\`\`
2.  Start the framework:
    \`\`\`bash
    sudo ${PROJECT_DIR}/start.sh
    \`\`\`
3.  Access the dashboard at http://127.0.0.1:5000 (default credentials: admin/${ADMIN_PASS}).
4.  Stop the framework:
    \`\`\`bash
    sudo ${PROJECT_DIR}/stop.sh
    \`\`\`

## Notes
- **Ethical Use**: This is a powerful tool. Only scan targets you have explicit permission to test to avoid legal issues.
EOF

#==========================================
# STEP 4: FINALIZE
#==========================================
log "Setting up Python virtual environment... 🐍"
python3 -m venv "$PYTHON_VENV_DIR"
source "$PYTHON_VENV_DIR/bin/activate"
pip3 install flask flask-wtf psycopg2-binary redis gunicorn celery python-dotenv requests flask-httpauth weasyprint google-generativeai markdown
deactivate

log "Finalizing permissions..."
chown -R $KALI_USER:$KALI_USER "$PROJECT_DIR"
mkdir -p "${PROJECT_DIR}/nucleifuzzer_output"
chown $KALI_USER:$KALI_USER "${PROJECT_DIR}/nucleifuzzer_output"
touch "${PROJECT_DIR}/logs/orchestrator.log"
chown $KALI_USER:$KALI_USER "${PROJECT_DIR}/logs/orchestrator.log"

log "--- ReconForge v42 (User-Agent Rotation Edition) Setup Complete! ✅ ---"
info "The PATH for Go tools has been added to the start script automatically."
log "To run the framework, use the new start script:"
warn "sudo ${PROJECT_DIR}/start.sh"
log "To stop ALL framework processes, use the new stop script:"
warn "sudo ${PROJECT_DIR}/stop.sh"
log "Access the dashboard at http://127.0.0.1:5000"
warn "Default credentials: admin / ${ADMIN_PASS}"


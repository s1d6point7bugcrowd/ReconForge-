***Still Under Construction***

<h1 align="center">ReconForge v1</h1>

<p align="center">
  <strong>An AI-Powered, Continuous Security Reconnaissance Framework</strong>
</p>

<p align="center">
    <a href="#"><img src="https://img.shields.io/badge/version-v1-blue.svg" alt="Version"></a>
    <a href="#"><img src="https://img.shields.io/badge/platform-Kali_Linux-lightgrey.svg" alt="Platform"></a>
    <a href="#"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
    <a href="#"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

---

**ReconForge** is a full-stack reconnaissance framework designed to automate and enhance the security assessment pipeline. It moves beyond simple tool-chaining by integrating a powerful AI core (Google's Gemini Pro) to analyze, interpret, and enrich findings. The result is a shift from raw data to actionable intelligence, all managed through a clean, modern web interface.

This framework is built for security professionals, bug bounty hunters, and red teams who need a centralized, persistent, and intelligent system to manage reconnaissance against multiple targets.

## Table of Contents
- [Key Features](#key-features)
- [The Gemini AI Core](#the-gemini-ai-core-)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Screenshots](#screenshots)
- [Ethical Disclaimer](#ethical-disclaimer)
- [Roadmap & Contributing](#roadmap--contributing)
- [License](#license)

## Key Features

- **🤖 AI-Powered Analysis**: The framework's standout feature. Uses Google Gemini Pro to provide deep analysis, impact assessment, and remediation for findings.
- **🕵️ Automated Recon Pipeline**: A logical chain of discovery: `Subfinder` for subdomain enumeration, `HTTPX` for live host verification, followed by a battery of scans.
- **🛡️ Comprehensive Vulnerability Scanning**: Leverages `Nuclei` for template-based scanning and `NucleiFuzzer` for deeper, parameter-aware fuzzing.
- **🤫 Advanced Secrets Detection**: Integrates `gitleaks` for repository scanning and a custom regex engine for finding secrets, keys, and endpoints in JavaScript files crawled by `Katana`.
- **🎭 User-Agent Rotation**: Evades basic WAFs and improves stealth by rotating through a list of real-world browser and mobile User-Agent strings for all scanning tools.
- **🖥️ Modern Web Dashboard**: A Flask-based UI provides a centralized place to manage targets, initiate scans, monitor progress, and view results.
- **⚡ Asynchronous Task Management**: Built on Celery and Redis, allowing for long-running, parallel scans without blocking the UI.
- **📄 PDF Reporting**: Generate professional PDF reports summarizing all findings for a target with a single click.
- **🚀 Performance Optimized**: Includes database indexing on frequently queried columns to ensure the UI remains fast and responsive, even with large datasets.

## The Gemini AI Core (🧠)

The integration with Gemini Pro transforms ReconForge from a simple scanner into an intelligent assistant. Instead of just showing you a finding, it tells you what it means.

* **Vulnerability Explanation & PoC Generation**
    When `Nuclei` finds a vulnerability, the raw JSON output is sent to Gemini. The AI then provides:
    1.  A clear, human-readable explanation of the vulnerability.
    2.  A concise summary of the potential business impact.
    3.  Step-by-step remediation advice for developers.
    4.  An actionable **`curl` command as a Proof of Concept** to instantly verify the finding.

* **In-Depth Secret Analysis**
    When `gitleaks` discovers a secret, Gemini analyzes the finding to determine:
    1.  The likely type of key or token.
    2.  The immediate risk and potential for abuse.
    3.  The correct protocol for revocation and removal from git history.

* **JavaScript Code Intelligence**
    While regex can find patterns, Gemini understands context. When a sensitive string is found in a `.js` file, the AI:
    1.  Analyzes the surrounding code to determine if it's a hardcoded key, an unprotected API endpoint, or PII.
    2.  Explains how an attacker could abuse the finding.
    3.  Generates a `curl` PoC to demonstrate the potential issue.

## Technology Stack

| Component         | Technology                                                                                                    |
| ----------------- | ------------------------------------------------------------------------------------------------------------- |
| **Backend** | Python 3, Flask, Gunicorn                                                                                     |
| **Task Queue** | Celery, Redis                                                                                                 |
| **Database** | PostgreSQL                                                                                                    |
| **AI Integration**| Google Gemini Pro                                                                                             |
| **Frontend** | HTML5, Bootstrap 5                                                                                            |
| **Recon Tools** | Subfinder, HTTPX, Nuclei, FFUF, Katana, Gitleaks, ParamSpider, NucleiFuzzer, and more.                          |

## Getting Started

### Prerequisites
- A Debian-based system (tested on **Kali Linux 2024.x / 2025.x**).
- `sudo` or `root` privileges for installation.
- A **Google Gemini API Key**. You can get one from [Google AI Studio](https://aistudio.google.com/app/apikey).
- (Optional) A **GitHub API Token** for higher rate limits when discovering repositories.

### Installation

The entire framework can be set up with a single script.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/ReconForge.git](https://github.com/your-username/ReconForge.git)
    cd ReconForge
    ```

2.  **Make the script executable:**
    ```bash
    chmod +x setup_reconforge.sh
    ```

3.  **Run the setup script as root:**
    ```bash
    sudo ./setup_reconforge.sh
    ```

4.  **Provide API Keys:** The script will prompt you to enter your Google Gemini API key and, optionally, your GitHub token. These are stored securely in an `.env` file.

The script handles all dependencies, database setup, Python environment creation, and file generation.

## Usage Guide

1.  **Start the Framework:**
    Use the provided start script. This will launch the Gunicorn web server and the Celery background worker.
    ```bash
    sudo /opt/reconforge/start.sh
    ```

2.  **Access the Dashboard:**
    Open your web browser and navigate to `http://127.0.0.1:5000`.
    
    The default credentials will be printed at the end of the setup script.
    -   **Username:** `admin`
    -   **Password:** `[A randomly generated password]`

3.  **Add a Target:**
    On the dashboard, enter a domain name (e.g., `example.com`) and, optionally, a direct URL to a Git repository. Click "Add/Update Target".

4.  **Run a Scan:**
    Once a target is added, click the green **Scan** button (`▶`) in its row. A scan task will be created, and you can monitor its status on the dashboard (e.g., `PENDING`, `PROGRESS`, `SUCCESS`).

5.  **View Results:**
    Click on the target's name to go to the details page. Here you'll find all discovered vulnerabilities, secrets, and other findings. For items analyzed by the AI, click the "🤖 Gemini AI Analysis" dropdown to see the detailed explanation and `curl` PoC.

6.  **Stop the Framework:**
    To stop all related processes (Gunicorn and Celery), use the stop script:
    ```bash
    sudo /opt/reconforge/stop.sh
    ```
    
p>

## Ethical Disclaimer
This tool is designed for authorized security testing and educational purposes only. Unauthorized scanning of networks and systems is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program. **Use responsibly.**

## Roadmap & Contributing
We welcome contributions! Feel free to open an issue or submit a pull request.

-   [ ] Integration with notification services (Slack, Discord).
-   [ ] More granular control over which scans to run per target.
-   [ ] Advanced AI chains for correlating multiple findings.
-   [ ] Support for Docker deployment.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

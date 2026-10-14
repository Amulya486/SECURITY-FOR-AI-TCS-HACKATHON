"""
mock_llm.py — Mock LLM response engine.

Provides realistic-looking responses for several models so the demo works without API keys.
Supports:
  • Knowledge base for domain queries (AI, Cloud, Encryption, Security, Databases)
  • Intelligent Document QA for attached / masked files (PDF, DOCX, TXT, Excel, Code)
  • Custom model response styles (GPT-4o, Claude 3.5, Gemini 1.5, Llama 3)
"""

import re
import random
import time
from typing import Optional, List, Dict, Tuple

# ── Available mock models ───────────────────────────────────────────
MODELS = {
    "GPT-4o (Mock)": {
        "style": "detailed",
        "icon": "🧠",
        "description": "OpenAI GPT-4o — balanced, structured, and in-depth answers.",
    },
    "Claude 3.5 (Mock)": {
        "style": "thoughtful",
        "icon": "🟣",
        "description": "Anthropic Claude 3.5 Sonnet — thoughtful, analytical, nuanced.",
    },
    "Gemini 1.5 (Mock)": {
        "style": "concise",
        "icon": "💎",
        "description": "Google Gemini 1.5 Pro — fast, concise, bulleted.",
    },
    "Llama 3 (Mock)": {
        "style": "casual",
        "icon": "🦙",
        "description": "Meta Llama 3 — conversational, practical developer vibe.",
    },
}


# ── Domain-Specific Knowledge Responses ─────────────────────────────

_CLOUD_COMPUTING_RESPONSE = """### ☁️ Cloud Computing: Definition & Core Concepts

**Cloud Computing** is the on-demand delivery of IT resources (servers, storage, databases, networking, software, and analytics) over the internet with pay-as-you-go pricing. Instead of buying, owning, and maintaining physical data centers, you rent computing capacity from providers like AWS, Microsoft Azure, or Google Cloud.

---

### 1. Essential Characteristics (NIST Model)
- **On-Demand Self-Service:** Provision resources automatically without human intervention from the provider.
- **Broad Network Access:** Capabilities are available over the network and accessed through standard client platforms (mobile phones, laptops, workstations).
- **Resource Pooling:** The provider's computing resources serve multiple consumers using a multi-tenant model.
- **Rapid Elasticity:** Capabilities can be elastically provisioned and released to scale rapidly outward and inward with demand.
- **Measured Service:** Resource usage is monitored, controlled, and billed transparently based on actual consumption.

---

### 2. Service Models (The Cloud Stack)
| Service Model | What It Provides | User Responsibility | Examples |
|---|---|---|---|
| **IaaS** (Infrastructure as a Service) | Virtual machines, storage, networking | OS, middleware, runtime, applications, data | AWS EC2, Azure VMs, Google Compute Engine |
| **PaaS** (Platform as a Service) | Managed runtime environments & development tools | Applications & data | AWS Elastic Beanstalk, Heroku, Google App Engine |
| **SaaS** (Software as a Service) | Fully functional end-user applications | Using the software | Google Workspace, Microsoft 365, Salesforce |

---

### 3. Deployment Models
- **Public Cloud:** Owned and operated by third-party cloud providers, shared across multiple tenants.
- **Private Cloud:** Cloud infrastructure dedicated exclusively to a single organization.
- **Hybrid Cloud:** Combines public and private clouds, allowing data and apps to be shared between them.
- **Multi-Cloud:** Using services from multiple distinct cloud providers to avoid vendor lock-in.

---

### 4. Key Supporting Concepts
- **Virtualization & Hypervisors:** Creating software-based (virtual) representations of servers and storage.
- **Containers & Orchestration:** Lightweight, portable application packaging (Docker) and management (Kubernetes).
- **Serverless Computing:** Running code in response to events without provisioning servers (AWS Lambda, Cloud Functions).
- **High Availability & Fault Tolerance:** Designing resilient systems that withstand infrastructure failures.
"""

_AI_ESSENTIALS_RESPONSE = """### 🤖 Essentials of Artificial Intelligence (AI)

**Artificial Intelligence (AI)** is the branch of computer science dedicated to creating systems capable of performing tasks that typically require human intelligence, such as visual perception, speech recognition, decision-making, reasoning, and language translation.

---

### 1. Core Hierarchy of AI
```
┌────────────────────────────────────────────────────────┐
│  ARTIFICIAL INTELLIGENCE (Broader field)               │
│  ┌──────────────────────────────────────────────────┐  │
│  │  MACHINE LEARNING (Learning from data)           │  │
│  │  ┌────────────────────────────────────────────┐  │  │
│  │  │  DEEP LEARNING (Multi-layer neural nets)   │  │  │
│  │  │  ┌──────────────────────────────────────┐  │  │  │
│  │  │  │  GENERATIVE AI & LLMs (Transformers) │  │  │  │
│  │  │  └──────────────────────────────────────┘  │  │  │
│  │  └────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

### 2. Key Subfields & Concepts
- **Machine Learning (ML):**
  - *Supervised Learning:* Training on labeled input-output pairs (e.g., classification, regression).
  - *Unsupervised Learning:* Discovering patterns and clusters in unlabeled data (e.g., k-means, PCA).
  - *Reinforcement Learning (RL):* Agents learning through trial-and-error rewards in an environment.
- **Deep Learning & Neural Networks:**
  - Multi-layer perceptrons, Convolutional Neural Networks (CNNs for images), and Recurrent/Transformer models (for sequences and text).
- **Natural Language Processing (NLP):**
  - Tokenization, embeddings, sentiment analysis, translation, and large language models (LLMs).
- **Computer Vision:**
  - Image classification, object detection, segmentation, and facial recognition.

---

### 3. Core Technical Elements
1. **Data & Features:** The foundation of AI models — data collection, cleaning, feature engineering, and labeling.
2. **Model Training & Loss Functions:** Optimizing mathematical parameters (weights & biases) using algorithms like Gradient Descent.
3. **Evaluation Metrics:** Accuracy, Precision, Recall, F1-score, ROC-AUC, Mean Squared Error (MSE).
4. **Inference:** Deploying trained models to make predictions on new, unseen data in production.

---

### 4. AI Safety & Ethics
- **Prompt Safety & Gateways:** Guarding against prompt injection, jailbreaks, and sensitive data leakage.
- **Bias & Fairness:** Mitigating discriminatory patterns inherited from training data.
- **Explainability (XAI):** Understanding why a model produced a particular prediction or output.
"""

_ENCRYPTION_RESPONSE = """### 🔐 Symmetric vs Asymmetric Encryption

| Feature | Symmetric (e.g., AES) | Asymmetric (e.g., RSA, ECC) |
|---|---|---|
| **Keys** | One shared secret key | Public + Private key pair |
| **Speed** | Very fast (hardware accelerated) | Slower (mathematically intensive) |
| **Use case** | Bulk data & disk encryption | Key exchange, digital signatures |
| **Key Exchange** | Must securely share key beforehand | Public key can be distributed freely |
| **Standards** | AES-256, ChaCha20 | RSA-4096, ECDSA, Ed25519 |

**In practice (Hybrid Cryptosystem):**
Modern security protocols like **TLS / HTTPS** combine both:
1. **Asymmetric crypto** securely establishes the connection and exchanges a temporary session key.
2. **Symmetric crypto (AES-256-GCM)** encrypts all high-speed data transferred during the session.

💡 *Golden rule:* Never create custom encryption algorithms in production — use audited, established cryptographic libraries (e.g., `cryptography`, `libsodium`, `OpenSSL`).
"""

_SECURITY_RESPONSE = """### 🛡️ Core Principles of Cybersecurity

1. **The CIA Triad:**
   - **Confidentiality:** Ensuring data is accessible only to authorized entities (encryption, access controls).
   - **Integrity:** Maintaining accuracy and consistency of data (hashing, digital signatures, checksums).
   - **Availability:** Ensuring reliable access to systems when needed (redundancy, DDoS protection, backups).

2. **Defense in Depth:**
   Implementing layered defenses so that if one security control fails, others remain active (firewalls, IDS/IPS, WAF, endpoint detection, prompt safety gateways).

3. **Zero Trust Architecture:**
   *"Never trust, always verify."* Every request must be authenticated, authorized, and continuously validated regardless of network perimeter.

4. **Least Privilege (PoLP):**
   Users and services are granted only the minimum permissions necessary to perform their specific tasks.
"""

_TCS_SECURITY_RESPONSE = """### 🛡️ Enterprise Security & Cryptographic Standards (e.g., TCS & Global IT Services)

Major enterprise IT service organizations (such as **TCS**, Infosys, Wipro, and global enterprises) adhere to industry-standard cryptographic algorithms and cybersecurity frameworks defined by **NIST**, **ISO/IEC 27001**, **FIPS 140-2/3**, and **PCI-DSS**:

---

### 1. Cryptographic Algorithms
| Purpose | Standard Algorithm | Key Length / Spec | Use Case |
|---|---|---|---|
| **Data at Rest Encryption** | **AES (Advanced Encryption Standard)** | AES-256-GCM / AES-256-CBC | Database, disk, and cloud bucket encryption |
| **Data in Transit Encryption** | **TLS 1.3 / HTTPS** | TLS_AES_256_GCM_SHA384 | Web portals, API gateways, VPN tunnels |
| **Key Exchange & Public Key PKI** | **RSA / ECC (ECDH, ECDSA)** | RSA 2048/4096-bit, Curve25519 | Digital signatures, SSL/TLS handshakes |
| **Cryptographic Hashing & Integrity** | **SHA-2 / SHA-3** | SHA-256, SHA-384, SHA-512 | Password hashing (bcrypt/Argon2id), checksums |
| **Message Authentication** | **HMAC** | HMAC-SHA256 | API request signing, token verification |

---

### 2. Core Security Architecture & Protocols
- **Zero Trust Architecture (ZTA):** Strict identity verification, micro-segmentation, and continuous device health checks before granting access.
- **Identity & Access Management (IAM):** Single Sign-On (SSO) backed by **SAML 2.0**, **OAuth 2.0**, and **OpenID Connect (OIDC)** with mandatory Multi-Factor Authentication (MFA).
- **Public Key Infrastructure (PKI):** Centralized Certificate Authorities (CA), HSMs (Hardware Security Modules), and automated certificate rotation.
- **Data Loss Prevention & Guardrails:** Prompt safety gateways, regex DLP scanning, and anomaly detection to prevent intellectual property leakage.
"""

# ── General Fallback Style Templates ────────────────────────────────

_RESPONSES = {
    "detailed": [
        (
            "Here is a comprehensive breakdown of your request:\n\n"
            "**Key Principles:**\n"
            "1. **Core Concept:** The foundation relies on clear architecture and modular design.\n"
            "2. **Implementation:** Best practices dictate decoupling components and enforcing input validation.\n"
            "3. **Security & Reliability:** Always follow the principle of least privilege and defense-in-depth.\n\n"
            "**Practical Example:**\n"
            "```python\n"
            "# Example implementation pattern\n"
            "def handle_request(payload: dict) -> dict:\n"
            "    sanitized = validate_and_clean(payload)\n"
            "    return execute_business_logic(sanitized)\n"
            "```\n\n"
            "Would you like to explore specific implementation details or architecture options?"
        ),
        (
            "Let's explore this step by step:\n\n"
            "**1. Theoretical Foundation:** Establishing the fundamental requirements and constraints.\n"
            "**2. Practical Execution:** Applying proven design patterns for scalability and maintainability.\n"
            "**3. Quality Assurance:** Rigorous testing, edge-case analysis, and security verification.\n\n"
            "Let me know which specific area you'd like to dive deeper into!"
        ),
    ],
    "thoughtful": [
        (
            "That's a thoughtful question, and there are several key angles to consider:\n\n"
            "From an **architectural standpoint**, the most effective solution balances performance, "
            "maintainability, and security constraints. Rather than choosing an overly complex setup, "
            "starting with modular components ensures long-term flexibility.\n\n"
            "**Key Considerations:**\n"
            "- **Trade-offs:** Every design choice trades off latency, throughput, or development velocity.\n"
            "- **Robustness:** Systems should fail gracefully and log informative diagnostics.\n\n"
            "Happy to tailor this further based on your specific requirements."
        ),
        (
            "Here is an analytical perspective on this topic:\n\n"
            "**Primary Considerations:**\n"
            "- **Simplicity vs Flexibility:** Keep interfaces clean while allowing underlying implementation to evolve.\n"
            "- **Security First:** Ensure boundary checks and sanitization happen at the gateway layer.\n\n"
            "Would you like to analyze specific use cases or edge cases?"
        ),
    ],
    "concise": [
        (
            "**Summary Overview:**\n\n"
            "• **Concept:** Clear separation of concerns with robust input validation.\n"
            "• **Key Steps:** 1. Analyze input → 2. Apply rules → 3. Process & return results.\n"
            "• **Best Practice:** Keep configurations modular and log significant operations.\n\n"
            "Let me know if you need specific code snippets or diagrams."
        ),
        (
            "**Direct Answer:**\n\n"
            "1. Define the system interface clearly.\n"
            "2. Apply defense-in-depth security principles.\n"
            "3. Verify and benchmark under expected workload.\n\n"
            "Ready for follow-up questions."
        ),
    ],
    "casual": [
        (
            "Great topic! Here is how it works in plain terms:\n\n"
            "Think of it like building a modular machine:\n"
            "- **Input Layer:** Inspects and cleans whatever comes in.\n"
            "- **Core Engine:** Does the heavy lifting and logic.\n"
            "- **Output Guard:** Ensures the result is safe and well-formatted.\n\n"
            "Hit me up if you want sample code or want to test a specific scenario! 🚀"
        ),
        (
            "Here's the rundown! 💡\n\n"
            "The key is keeping things simple and well-structured. Use proven tools, "
            "test your edge cases, and ensure safety checks are in place before shipping to production.\n\n"
            "What part should we build next? 🛠️"
        ),
    ],
}


# ── Intelligent Document Response Generator ─────────────────────────

def _generate_document_response(user_query: str, doc_filename: str, doc_body: str, model_name: str) -> str:
    """
    Generate an intelligent response based on the actual text extracted from the document
    (including masked entities).
    """
    clean_body = doc_body.strip()
    
    # Split text by pages or paragraphs
    pages = [p.strip() for p in re.split(r"--- Page \d+ ---", clean_body) if p.strip()]
    raw_lines = [l.strip() for l in clean_body.splitlines() if l.strip() and not l.strip().startswith("--- Page")]

    # Check for masked tokens
    masked_tokens_found = set(re.findall(r"\[[A-Z\s\(\)/_-]+\]", doc_body))
    masked_notice = ""
    if masked_tokens_found:
        tokens_list = ", ".join(f"`{t}`" for t in sorted(masked_tokens_found))
        masked_notice = (
            f"\n\n> 🛡️ **Gateway Redaction Notice:** Sensitive fields in this document were masked "
            f"before processing: {tokens_list}."
        )

    # Extract sections & key topics from document
    topics_found = []
    bullet_items = []
    for line in raw_lines:
        if len(line) < 160 and (":" in line or line.startswith(("#", "•", "-", "*", "1.", "2.", "3.", "4.", "5.")) or line.isupper()):
            clean_l = line.lstrip("#•-* ").strip()
            if clean_l and clean_l not in topics_found:
                topics_found.append(clean_l)
        elif len(line) > 15:
            bullet_items.append(line)

    query_lower = user_query.lower()
    
    # Check if query asks for summary
    is_summary_req = any(kw in query_lower for kw in ["summarize", "summary", "overview", "what is this", "explain", "about", "brief", "describe", "notes"])
    
    # Keyword matches in doc
    matching_excerpts = []
    query_words = [w for w in re.findall(r"\w+", query_lower) if len(w) > 2 and w not in ["tell", "give", "from", "this", "that", "what", "with", "have", "attached", "document", "file", "please", "summary", "summarize", "show"]]
    if query_words:
        for line in raw_lines:
            line_l = line.lower()
            if any(w in line_l for w in query_words):
                matching_excerpts.append(line.lstrip("#•-* ").strip())

    # Format structured extracted details (show full list if reasonably sized <= 30 items)
    max_items = 30 if len(topics_found) <= 30 else 18
    preview_topics = topics_found[:max_items] if topics_found else raw_lines[:max_items]
    structured_bullets = [f"- **{t.split(':', 1)[0]}:** {t.split(':', 1)[1].strip()}" if ":" in t and not t.startswith("http") else f"- {t}" for t in preview_topics]
    bullets_text = "\n".join(structured_bullets) if structured_bullets else "- Document text extracted successfully."

    excerpts_section = ""
    if matching_excerpts and not is_summary_req:
        top_matches = matching_excerpts[:10]
        excerpts_section = "\n\n**🔎 Key Matches for Your Query:**\n" + "\n".join(f"> • {m}" for m in top_matches)

    # Build response
    header = f"### 📄 Analysis of Attached Document: `{doc_filename}`\n\n"

    # Multi-page breakdown if PDF has multiple pages
    pages_summary = ""
    if len(pages) > 1:
        pages_summary = f"\n\n**Document Structure:**\n- Total Pages Analyzed: **{len(pages)} pages**\n- Total Characters: **{len(clean_body):,}** across **{len(raw_lines)} text segments**"

    if is_summary_req or not user_query.strip():
        resp = (
            f"{header}"
            f"Here is a comprehensive summary of **{doc_filename}** based on the extracted content:\n\n"
            f"**Key Topics & Extracted Information:**\n"
            f"{bullets_text}"
            f"{excerpts_section}"
            f"{pages_summary}"
            f"\n\n**Main Overview:**\n"
            f"The document covers foundational records and structured information outlined above. "
            f"You can ask me to search, filter, or explain any specific field or section from this file in greater depth."
            f"{masked_notice}"
        )
    else:
        resp = (
            f"{header}"
            f"Based on your query (*\"{user_query}\"*), here is the information extracted from **{doc_filename}**:\n\n"
            f"**Extracted Information & Record Details:**\n"
            f"{bullets_text}"
            f"{excerpts_section}"
            f"{pages_summary}"
            f"\n\nLet me know if you need further details or specific queries answered from this document!"
            f"{masked_notice}"
        )

    return resp


def _generate_tax_receipts_response(prompt: str, masked_tokens: list) -> str:
    masked_note = ""
    if masked_tokens:
        tok_str = ", ".join(f"`{t}`" for t in masked_tokens)
        masked_note = f"\n\n> 🛡️ **Gateway Redaction:** Your private tax ID was sanitized ({tok_str}) before processing."

    return f"""### 📑 Tax Receipts, ITR Acknowledgements & Form 26AS Recovery Guide

If you are looking for tax receipts or filed tax returns linked to your PAN / Tax ID and cannot locate them on your local drive, here are the official ways to retrieve them:

---

### 1. Retrieve Directly from the Income Tax e-Filing Portal
1. **Log in:** Visit [incometax.gov.in](https://www.incometax.gov.in) using your **PAN** and password.
2. **Download Filed ITRs & Receipts (ITR-V):**
   - Navigate to **e-File** → **Income Tax Returns** → **View Filed Returns**.
   - Select the relevant Assessment Year (e.g., AY 2025-26, AY 2024-25).
   - Click **Download Receipt (ITR-V)** or **Download Form**.
3. **Download Form 26AS (Tax Credit Statement / TDS Receipts):**
   - Go to **e-File** → **Income Tax Returns** → **View Form 26AS**.
   - You will be redirected to the TRACES portal where you can export all TDS / TCS tax credits as PDF.
4. **Annual Information Statement (AIS / TIS):**
   - Click on the **AIS** tab on the top menu to view all reported financial transactions and tax deductions.

---

### 2. Search Shortcuts for Local & Cloud Drives
If you suspect the files are on your Google Drive, OneDrive, or local computer, use these search queries:
- **Google Drive / OneDrive Search:**
  ```text
  type:pdf "ITR" OR "Form 16" OR "26AS" OR "Ack No"
  ```
- **Windows File Explorer (Search Bar):**
  ```text
  ext:pdf name:*ITR* OR name:*Tax* OR name:*Form16*
  ```
- **Default File Naming Conventions:**
  - `ITR-V_<PAN>_<AY>.pdf`
  - `Form16_PartA_<AY>.pdf`
  - `TaxReceipt_<Date>.pdf`

---

### 3. Retrieve from Your Employer / Bank
- **Salary TDS (Form 16):** Contact your employer's payroll / HRMS portal (Workday, Darwinbox, Keka) under the **Tax Declarations / Form 16** tab.
- **Advance Tax / Self-Assessment Challan Receipts:** Go to **e-File** → **e-Pay Tax** → **Payment History** on the Income Tax portal to re-download the BSR challan receipt.{masked_note}
"""


# ── Public API ──────────────────────────────────────────────────────

def get_response(prompt: str, model_name: str) -> str:
    """
    Return an LLM response (mocked for demo).

    To integrate a real API:
      1. Add API keys to st.secrets or environment variables (.env).
      2. Replace this function body with an OpenAI / Anthropic / Gemini SDK call.
      3. Keep the same signature so the rest of the application runs seamlessly.
    """
    # Simulate network latency
    time.sleep(random.uniform(0.3, 0.7))

    # 1. Check if prompt contains attached document context (matches all header formats)
    doc_match = re.search(r"\[(?:Attached Document Context|Document|Attached Document)[^\]]*\]:\s*([\s\S]*)", prompt)
    if doc_match:
        body = doc_match.group(1).strip()
        user_query = prompt[:doc_match.start()].strip()
        
        # Extract filename cleanly from header
        header_text = prompt[doc_match.start():prompt.find("]:", doc_match.start()) + 2]
        clean_fn = re.sub(r"^\[(?:Attached Document Context|Document|Attached Document)\s*(?:\(Masked\))?\s*[:\(\s]*", "", header_text)
        clean_fn = re.sub(r"[\)\]:\s]+$", "", clean_fn).strip()
        doc_filename = clean_fn if clean_fn else "Attached Document"
        
        return _generate_document_response(user_query, doc_filename, body, model_name)

    lower = prompt.lower()
    masked_tokens = list(set(re.findall(r"\[[A-Z\s\(\)/_-]+\]", prompt)))

    # 2. Topic-specific matches for standalone prompts
    if any(kw in lower for kw in ["tax", "receipt", "form 16", "26as", "itr", "pan", "tds", "challan", "locate on my drive", "tax receipts"]):
        return _generate_tax_receipts_response(prompt, masked_tokens)

    if any(kw in lower for kw in ["tcs", "enterprise security", "security algorithm", "infosys", "wipro", "cryptographic standards"]):
        return _TCS_SECURITY_RESPONSE

    if any(kw in lower for kw in ["cloud", "iaas", "paas", "saas", "aws", "azure"]):
        return _CLOUD_COMPUTING_RESPONSE

    if any(kw in lower for kw in ["ai", "artificial intelligence", "machine learning", "deep learning", "neural network", "llm", "essentials of ai"]):
        return _AI_ESSENTIALS_RESPONSE

    if any(kw in lower for kw in ["encrypt", "symmetric", "asymmetric", "aes", "rsa", "cipher"]):
        return _ENCRYPTION_RESPONSE

    if any(kw in lower for kw in ["cybersecurity", "cia triad", "zero trust", "firewall", "security principles"]):
        return _SECURITY_RESPONSE

    if any(kw in lower for kw in ["database", "sql", "nosql", "relational", "postgres", "mongodb"]):
        return _DATABASE_RESPONSE

    # 3. Fallback to model-specific style template
    style = MODELS.get(model_name, {}).get("style", "detailed")
    responses = _RESPONSES.get(style, _RESPONSES["detailed"])
    base_resp = random.choice(responses)

    if masked_tokens:
        tok_str = ", ".join(f"`{t}`" for t in masked_tokens)
        base_resp += f"\n\n> 🛡️ **Gateway Redaction Notice:** The query was processed safely with sanitized tokens: {tok_str}."

    return base_resp


def get_model_names() -> list:
    """Return sorted list of model display names."""
    return list(MODELS.keys())


def get_model_info(model_name: str) -> dict:
    """Return icon and description for a model."""
    return MODELS.get(model_name, {"icon": "🤖", "description": "Unknown model"})

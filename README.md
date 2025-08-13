# 🌐 Threat Intel Feed Aggregator

I built this to pull multiple threat intelligence feeds into a single view — so I don’t have to jump between tabs and manually deduplicate indicators during investigations.

The tool grabs IOCs (IPs, domains, URLs, hashes) from sources like OTX, AbuseIPDB, and any custom feed I point it to, merges them, removes duplicates, and lets me export them in seconds.

---

## 🚀 Features

- **Multiple Feed Support** — Pull data from OTX, AbuseIPDB, and custom JSON feeds.
- **IOC Types** — Handles IPv4, domains, URLs, MD5/SHA1/SHA256 hashes.
- **De-duplication** — Removes duplicates across feeds.
- **Feed Comparison** — See which feeds contain the same indicators.
- **Export Options** — CSV or JSON download for further analysis.
- **Lightweight Backend** — FastAPI-powered API for speed and easy integration.

---

## 📸 Screenshots

**Aggregated IOC List**  
![Aggregated IOC List](./screenshots/aggregated_view.png)

**Feed Source Comparison**  
![Feed Comparison View](./screenshots/feed_comparison_view.png)

---

## ⚙️ Setup

```bash
# Clone repository
git clone https://github.com/<your-username>/threat-intel-feed-aggregator.git
cd threat-intel-feed-aggregator

# Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate   # Mac/Linux

# Install dependencies
pip install -r requirements.txt
▶️ Run
Backend (FastAPI)
bash
Copy
Edit
cd backend
python -m uvicorn app:app --reload --port 8002
Frontend
Open frontend/index.html in your browser.

📂 Project Structure
pgsql
Copy
Edit
threat-intel-feed-aggregator/
│   README.md
│   requirements.txt
│   .gitignore
│
├── backend/
│   └── app.py
│
├── frontend/
│   └── index.html
│
├── data/
│   ├── feed_otx.json
│   ├── feed_abuseipdb.json
│   └── feed_custom.json
│
└── screenshots/
    ├── aggregated_view.png
    └── feed_comparison_view.png
🛠️ Stack
Backend: FastAPI (Python)

Frontend: Bootstrap 5, Vanilla JS

Data: JSON

Integration: OTX, AbuseIPDB, custom feeds

💡 Why I built this
Switching between multiple threat intel portals slows me down during an investigation.
This tool lets me grab and compare feeds in one place — a single pane of glass for faster triage.
It’s small enough to run locally but flexible enough to extend with other APIs.

📜 License
MIT — free to use and modify.
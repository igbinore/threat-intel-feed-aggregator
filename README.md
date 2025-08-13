🛰 Threat Intel Feed Aggregator
I built this to consolidate multiple threat intelligence feeds into one clean, deduplicated view.
Instead of bouncing between OTX, AbuseIPDB, and custom lists, I can now pull them together, filter, and export for investigations.

🚀 Features
Multi-feed aggregation – pulls from OTX, AbuseIPDB, and custom feeds.

De-duplication with counts – groups repeated indicators and shows frequency.

IOC type filtering – focus on IPs, domains, URLs, hashes, etc.

Export options – CSV, JSON, or ZIP bundle (both formats).

Beautiful UI – clean dashboard with light/dark mode toggle.

Local & fast – runs on your machine, no data leaves your environment.

📸 Screenshots
Main Dashboard – Light Mode

Main Dashboard – Dark Mode

Export Options View

⚙️ Setup
bash
Copy
Edit
# Clone the repo
git clone https://github.com/igbinore/threat-intel-feed-aggregator.git
cd threat-intel-feed-aggregator

# Create & activate virtual environment
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
uvicorn app:app --reload --port 8002
Frontend
Open frontend/index.html in your browser.

🧱 Structure
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
    ├── dashboard_light.png
    ├── dashboard_dark.png
    └── export_view.png
🛠️ Tech Stack
Backend: FastAPI (Python)

Frontend: Bootstrap 5, Vanilla JS

Data: JSON feeds from OTX, AbuseIPDB, and custom sources

Exports: CSV / JSON / ZIP

💡 Why I built this
When working incidents, I noticed I was wasting time flipping between threat intel sources.
This tool pulls them together, strips duplicates, and lets me export everything cleanly.
It’s built to be simple, local, and easy to extend with new feeds.

📜 License
MIT — use it, tweak it, share it.
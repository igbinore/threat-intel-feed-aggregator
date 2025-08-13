🛰 Threat Intel Feed Aggregator

I built this project to save time when gathering and reviewing threat intelligence.
Instead of visiting multiple platforms one by one, I wanted a single dashboard that pulls in feeds from different sources, lets me filter, and gives me export-ready data for investigations.

🚀 What It Does

Aggregate multiple threat intel feeds – AbuseIPDB, AlienVault OTX, and a custom feed.

Clean & normalize data – No more mismatched formats between sources.

Search & filter – Quickly find specific IPs, domains, or indicators.

Export – Save current view to CSV or JSON in one click.

Lightweight UI – Runs locally, no heavy setup required.


📸 Screenshot example
![Dashboard Screenshot](./screenshots/dashboard_light.png)



⚙️ Setup
1. Clone the repo
git clone https://github.com/igbinore/threat-intel-feed-aggregator.git
cd threat-intel-feed-aggregator

2. Create a virtual environment & install dependencies
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate   # Mac/Linux

pip install -r requirements.txt

3. Run the backend (FastAPI)
cd backend
uvicorn app:app --reload --port 8001

4. Open the frontend

Just open frontend/index.html in your browser.

## 🧱 Project Structure

```text
threat-intel-feed-aggregator/
├─ README.md
├─ requirements.txt
├─ backend/
│  └─ app.py
├─ frontend/
│  └─ index.html
├─ data/
│  ├─ feed_abuseipdb.json
│  ├─ feed_otx.json
│  └─ feed_custom.json
└─ screenshots/
   └─ dashboard_light.png

🛠 Tech Stack

Backend: FastAPI (Python)

Frontend: HTML, Bootstrap 5, Vanilla JS

Data Handling: Pandas

Exports: CSV, JSON

💡 Why I Built This

Pulling threat intel from multiple portals was slowing me down in investigations. I wanted a simple, extendable tool I can run locally and integrate into my workflow. This version already covers the basics, but adding enrichment APIs (like VirusTotal, AbuseIPDB lookups) will make it even more powerful.

📜 License
MIT — free to use and modify.
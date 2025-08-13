from fastapi import FastAPI, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from typing import List, Optional
import os, json, glob, io, pandas as pd, zipfile

app = FastAPI(title="Threat Intel Feed Aggregator", version="0.1.0")

# CORS for local frontend file
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

def load_feeds() -> pd.DataFrame:
    rows = []
    for path in glob.glob(os.path.join(DATA_DIR, "feed_*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    t = (item.get("type") or "").lower()
                    v = item.get("value")
                    src = item.get("source") or "Unknown"
                    fs = item.get("first_seen")
                    if not v or not t:
                        continue
                    rows.append({"type": t, "value": str(v), "source": src, "first_seen": fs})
        except Exception:
            continue
    df = pd.DataFrame(rows, columns=["type","value","source","first_seen"])
    if df.empty:
        return pd.DataFrame(columns=["type","value","source","first_seen","count"])
    df["count"] = 1
    df = (
        df.groupby(["type","value","source","first_seen"], dropna=False)["count"]
          .sum()
          .reset_index()
          .sort_values(["type","count","value"], ascending=[True, False, True])
          .reset_index(drop=True)
    )
    return df

def apply_filters(df: pd.DataFrame, f_types: List[str], f_sources: List[str], q: Optional[str]) -> pd.DataFrame:
    if df.empty:
        return df
    if f_types:
        low = [t.lower() for t in f_types]
        df = df[df["type"].isin(low)]
    if f_sources:
        df = df[df["source"].isin(f_sources)]
    if q:
        df = df[df["value"].str.contains(q, case=False, na=False)]
    return df.reset_index(drop=True)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/aggregate")
def aggregate(
    type: Optional[List[str]] = Query(default=None, alias="type"),
    source: Optional[List[str]] = Query(default=None, alias="source"),
    q: Optional[str] = Query(default=None),
):
    df = load_feeds()
    all_sources = sorted(df["source"].dropna().unique().tolist()) if not df.empty else []
    all_types = sorted(df["type"].dropna().unique().tolist()) if not df.empty else []
    df = apply_filters(df, type or [], source or [], q)
    total = int(df["count"].sum()) if not df.empty else 0
    by_type = df.groupby("type")["count"].sum().to_dict() if not df.empty else {}
    by_source = df.groupby("source")["count"].sum().to_dict() if not df.empty else {}
    return JSONResponse({
        "total": total,
        "by_type": by_type,
        "by_source": by_source,
        "available": {"types": all_types, "sources": all_sources},
        "items": df.to_dict(orient="records")
    })

@app.post("/export")
async def export(format: str = Form(...), items: str = Form(...)):
    data = json.loads(items)
    df = pd.DataFrame(data)
    if format.lower() == "csv":
        buf = io.StringIO()
        (df if not df.empty else pd.DataFrame(columns=["type","value","source","first_seen","count"])) \
            .to_csv(buf, index=False)
        buf.seek(0)
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="intel.csv"'}
        )
    payload = json.dumps(data, indent=2).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="intel.json"'}
    )

@app.post("/export-zip")
async def export_zip(items: str = Form(...)):
    data = json.loads(items)
    df = pd.DataFrame(data)
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        csv_buf = io.StringIO()
        (df if not df.empty else pd.DataFrame(columns=["type","value","source","first_seen","count"])) \
            .to_csv(csv_buf, index=False)
        zf.writestr("intel.csv", csv_buf.getvalue())
        zf.writestr("intel.json", json.dumps(data, indent=2))
    mem_zip.seek(0)
    return StreamingResponse(
        mem_zip,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="intel_bundle.zip"'}
    )

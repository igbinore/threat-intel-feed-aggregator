# backend/app.py
from __future__ import annotations
import os, sqlite3, hashlib, json, io, zipfile
from datetime import datetime
from typing import List, Optional, Dict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

DB_PATH = os.getenv("TIA_DB", "data/indicators.db")
Path("data").mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Threat Intel Feed Aggregator", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

VALID_TYPES = {"ip", "domain", "url", "hash", "email"}

def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS indicators (
            id TEXT PRIMARY KEY,
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            tags_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_type ON indicators(type);
        CREATE INDEX IF NOT EXISTS idx_source ON indicators(source);
        CREATE INDEX IF NOT EXISTS idx_last_seen ON indicators(last_seen);
        CREATE INDEX IF NOT EXISTS idx_indicator ON indicators(indicator);
        """)
init_db()

def _id(indicator: str, type_: str, source: str) -> str:
    payload = f"{indicator.strip().lower()}|{type_.strip().lower()}|{source.strip().lower()}"
    return hashlib.sha1(payload.encode()).hexdigest()

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def merge_tags(existing_json: str, new_tags: List[str]) -> str:
    try:
        existing = json.loads(existing_json) if existing_json else []
    except Exception:
        existing = []
    merged = sorted({str(t).strip().lower() for t in (existing + (new_tags or [])) if str(t).strip()})
    return json.dumps(merged)

class IndicatorIn(BaseModel):
    indicator: str
    type: str
    source: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = []

    @field_validator("type")
    @classmethod
    def _t(cls, v: str) -> str:
        v2 = v.lower().strip()
        if v2 not in VALID_TYPES:
            raise ValueError(f"type must be one of {sorted(VALID_TYPES)}")
        return v2

    @field_validator("indicator","source")
    @classmethod
    def _nb(cls, v: str) -> str:
        if not str(v).strip():
            raise ValueError("field cannot be blank")
        return v.strip()

class IndicatorOut(BaseModel):
    id: str
    indicator: str
    type: str
    source: str
    first_seen: str
    last_seen: str
    tags: List[str]

@app.get("/health")
def health():
    return {"ok": True, "version": app.version}

@app.post("/indicators", response_model=IndicatorOut)
def upsert(item: IndicatorIn):
    _key = _id(item.indicator, item.type, item.source)
    fs = item.first_seen or now_iso()
    ls = item.last_seen or now_iso()
    with connect() as conn:
        row = conn.execute("SELECT * FROM indicators WHERE id=?", (_key,)).fetchone()
        if row:
            new_first = min(row["first_seen"], fs)
            new_last  = max(row["last_seen"], ls)
            new_tags  = merge_tags(row["tags_json"], item.tags)
            conn.execute("UPDATE indicators SET first_seen=?, last_seen=?, tags_json=? WHERE id=?",
                         (new_first, new_last, new_tags, _key))
        else:
            tags_json = json.dumps(sorted({t.strip().lower() for t in item.tags if str(t).strip()}))
            conn.execute(
                "INSERT INTO indicators(id,indicator,type,source,first_seen,last_seen,tags_json) VALUES(?,?,?,?,?,?,?)",
                (_key, item.indicator.strip(), item.type, item.source.strip(), fs, ls, tags_json)
            )
        conn.commit()
        row = conn.execute("SELECT * FROM indicators WHERE id=?", (_key,)).fetchone()
    return IndicatorOut(
        id=row["id"], indicator=row["indicator"], type=row["type"], source=row["source"],
        first_seen=row["first_seen"], last_seen=row["last_seen"],
        tags=json.loads(row["tags_json"]) if row["tags_json"] else []
    )

@app.get("/indicators", response_model=List[IndicatorOut])
def search(
    q: Optional[str] = None,
    type: Optional[str] = None,
    source: Optional[str] = None,
    tag: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    sort: str = "last_seen:desc",
    limit: int = 200,
    offset: int = 0,
):
    clauses, params = [], []
    if q:      clauses.append("indicator LIKE ?") or params.append(f"%{q.strip()}%")
    if type:
        t = type.strip().lower()
        if t not in VALID_TYPES: raise HTTPException(400, f"invalid type; must be {sorted(VALID_TYPES)}")
        clauses.append("type=?"); params.append(t)
    if source: clauses.append("LOWER(source)=?") or params.append(source.strip().lower())
    if since:  clauses.append("last_seen >= ?") or params.append(since)
    if until:  clauses.append("last_seen <= ?") or params.append(until)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    field, _, direction = (sort or "last_seen:desc").partition(":")
    field = field.strip().lower(); direction = (direction or "desc").strip().lower()
    if field not in {"first_seen","last_seen"}: field = "last_seen"
    if direction not in {"asc","desc"}: direction = "desc"
    order_sql = f"ORDER BY {field} {direction.upper()}"

    sql = f"SELECT * FROM indicators {where_sql} {order_sql} LIMIT ? OFFSET ?"
    params += [limit, offset]
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    out: List[IndicatorOut] = []
    for r in rows:
        tags = json.loads(r["tags_json"]) if r["tags_json"] else []
        if tag and tag.strip().lower() not in [t.lower() for t in tags]:  # filter by tag if provided
            continue
        out.append(IndicatorOut(
            id=r["id"], indicator=r["indicator"], type=r["type"], source=r["source"],
            first_seen=r["first_seen"], last_seen=r["last_seen"], tags=tags
        ))
    return out

@app.delete("/indicators/{id}", status_code=204)
def delete_indicator(id: str):
    with connect() as conn:
        cur = conn.execute("DELETE FROM indicators WHERE id=?", (id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
        conn.commit()
    return None

@app.get("/aggregate")
def aggregate(q: Optional[str]=None, type: Optional[str]=None, source: Optional[str]=None, since: Optional[str]=None, until: Optional[str]=None):
    items = search(q=q, type=type, source=source, since=since, until=until, limit=1000)
    total = len(items)
    type_counts: Dict[str,int] = {}
    source_counts: Dict[str,int] = {}
    for it in items:
        type_counts[it.type] = type_counts.get(it.type,0)+1
        source_counts[it.source] = source_counts.get(it.source,0)+1
    top_type = max(type_counts.items(), key=lambda x:x[1])[0] if type_counts else None
    top_source = max(source_counts.items(), key=lambda x:x[1])[0] if source_counts else None
    return {
        "total": total,
        "type_counts": type_counts,
        "source_counts": source_counts,
        "top_type": {"type": top_type, "count": type_counts.get(top_type,0)} if top_type else None,
        "top_source": {"source": top_source, "count": source_counts.get(top_source,0)} if top_source else None,
    }

class ExportBody(BaseModel):
    format: str = "csv"
    q: Optional[str] = None
    type: Optional[str] = None
    source: Optional[str] = None
    since: Optional[str] = None
    until: Optional[str] = None

@app.post("/export")
def export(body: ExportBody):
    items = search(q=body.q, type=body.type, source=body.source, since=body.since, until=body.until, limit=1000)
    if body.format.lower() == "json":
        data = json.dumps([i.model_dump() for i in items], indent=2)
        return Response(content=data, media_type="application/json")
    headers = ["type","indicator","source","first_seen","last_seen","tags"]
    lines = [",".join(headers)]
    for i in items:
        vals = [i.type, i.indicator, i.source, i.first_seen, i.last_seen, "|".join(i.tags or [])]
        lines.append(",".join(['"{}"'.format(str(v).replace('"','""')) for v in vals]))
    return Response(content="\r\n".join(lines), media_type="text/csv")

@app.post("/export-zip")
def export_zip(body: ExportBody):
    items = search(q=body.q, type=body.type, source=body.source, since=body.since, until=body.until, limit=1000)
    csv_headers = ["type","indicator","source","first_seen","last_seen","tags"]
    csv_lines = [",".join(csv_headers)]
    for i in items:
        vals = [i.type, i.indicator, i.source, i.first_seen, i.last_seen, "|".join(i.tags or [])]
        csv_lines.append(",".join(['"{}"'.format(str(v).replace('"','""')) for v in vals]))
    csv_bytes = "\r\n".join(csv_lines).encode()
    json_bytes = json.dumps([i.model_dump() for i in items], indent=2).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("indicators.csv", csv_bytes)
        z.writestr("indicators.json", json_bytes)
    buf.seek(0)
    return Response(content=buf.read(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="export.zip"'})

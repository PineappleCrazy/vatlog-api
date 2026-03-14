from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from typing import List
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
API_KEY      = os.getenv("API_KEY")

# ── Database setup ──────────────────────────────────────────
engine       = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base         = declarative_base()

class LogEntry(Base):
    __tablename__ = "logs"
    id    = Column(Integer, primary_key=True, index=True)
    fir   = Column(String)
    time  = Column(String)
    value = Column(Integer)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ── Auth ────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key")

def verify_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return key

# ── Schemas ─────────────────────────────────────────────────
class EntryIn(BaseModel):
    fir:   str
    time:  str
    value: int

class EntryOut(EntryIn):
    id: int
    class Config:
        from_attributes = True

# ── App ─────────────────────────────────────────────────────
app = FastAPI()

@app.post("/logs", response_model=List[EntryOut])
def add_logs(entries: List[EntryIn], db: Session = Depends(get_db), _: str = Depends(verify_key)):
    created = []
    for e in entries:
        row = LogEntry(fir=e.fir, time=e.time, value=e.value)
        db.add(row)
        created.append(row)
    db.commit()
    for row in created:
        db.refresh(row)
    return created

@app.get("/logs", response_model=List[EntryOut])
def get_logs(db: Session = Depends(get_db), _: str = Depends(verify_key)):
    return db.query(LogEntry).all()
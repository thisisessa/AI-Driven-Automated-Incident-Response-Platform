from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()
engine = create_engine('sqlite:///evidence_vault/custody_ledger.db', echo=False)
SessionLocal = sessionmaker(bind=engine)

class ChainOfCustody(Base):
    __tablename__ = 'custody_logs'
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String)
    evidence_name = Column(String)
    sha256_hash = Column(String)
    action = Column(String)
    timestamp = Column(String, default=lambda: datetime.utcnow().isoformat())
    integrity_status = Column(String, default="VALID")

Base.metadata.create_all(engine)

"""
SQLAlchemy database models for AegisProbe AI.
Stores projects, targets, scans, tests, findings, evidence, and reports.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class TargetRecord(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(512), unique=True, nullable=False, index=True)
    name = Column(String(256), nullable=True)
    description = Column(Text, nullable=True)
    is_lab = Column(Boolean, default=False)
    authorized = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship("ScanRecord", back_populates="target_rel", cascade="all, delete-orphan")


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    target_url = Column(String(512), nullable=False)
    status = Column(String(32), default="COMPLETED")  # PENDING, RUNNING, COMPLETED, FAILED
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(32), default="INFO")
    modules_scanned = Column(JSON, default=list)
    total_tests = Column(Integer, default=0)
    passed_tests = Column(Integer, default=0)
    failed_tests = Column(Integer, default=0)

    target_rel = relationship("TargetRecord", back_populates="scans")
    findings = relationship("FindingRecord", back_populates="scan", cascade="all, delete-orphan")


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey("scans.id"), nullable=False, index=True)
    finding_id = Column(String(32), nullable=False)  # PI-001, JB-003, etc.
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    confidence = Column(String(16), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    references = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("ScanRecord", back_populates="findings")

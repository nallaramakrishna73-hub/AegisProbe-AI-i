"""
Database repository for AegisProbe AI.
Provides CRUD operations for scans, findings, targets, and reports.
"""

from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timezone

from aegisprobe.config import load_config
from aegisprobe.database.models import Base, TargetRecord, ScanRecord, FindingRecord
from aegisprobe.core.findings import Finding


class DatabaseRepository:
    def __init__(self, db_url: Optional[str] = None):
        cfg = load_config()
        self.url = db_url or cfg.database_url or "sqlite:///aegisprobe.db"
        self.engine = create_engine(
            self.url,
            connect_args={"check_same_thread": False} if self.url.startswith("sqlite") else {},
            echo=False
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()

    def save_scan(
        self,
        scan_id: str,
        target_url: str,
        modules: List[str],
        risk_score: float,
        risk_level: str,
        total_tests: int,
        passed_tests: int,
        failed_tests: int,
        findings: List[Finding]
    ) -> ScanRecord:
        with self.get_session() as session:
            # Upsert target
            target = session.query(TargetRecord).filter(TargetRecord.url == target_url).first()
            if not target:
                target = TargetRecord(url=target_url, is_lab="lab" in target_url or "127.0.0.1" in target_url)
                session.add(target)
                session.flush()

            scan = ScanRecord(
                id=scan_id,
                target_id=target.id,
                target_url=target_url,
                status="COMPLETED",
                completed_at=datetime.now(timezone.utc),
                risk_score=risk_score,
                risk_level=risk_level,
                modules_scanned=modules,
                total_tests=total_tests,
                passed_tests=passed_tests,
                failed_tests=failed_tests
            )
            session.add(scan)
            session.flush()

            for f in findings:
                fr = FindingRecord(
                    scan_id=scan.id,
                    finding_id=f.id,
                    title=f.title,
                    category=f.category,
                    severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                    description=f.description,
                    evidence=f.evidence,
                    impact=f.impact,
                    remediation=f.remediation,
                    references=f.references
                )
                session.add(fr)

            session.commit()
            session.refresh(scan)
            return scan

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            scans = session.query(ScanRecord).order_by(ScanRecord.started_at.desc()).limit(limit).all()
            results = []
            for s in scans:
                results.append({
                    "id": s.id,
                    "target_url": s.target_url,
                    "status": s.status,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "risk_score": s.risk_score,
                    "risk_level": s.risk_level,
                    "modules_scanned": s.modules_scanned or [],
                    "total_tests": s.total_tests,
                    "passed_tests": s.passed_tests,
                    "failed_tests": s.failed_tests,
                    "findings_count": len(s.findings)
                })
            return results

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self.get_session() as session:
            s = session.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
            if not s:
                return None
            findings_data = []
            for f in s.findings:
                findings_data.append({
                    "id": f.finding_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "references": f.references or []
                })
            return {
                "id": s.id,
                "target_url": s.target_url,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "risk_score": s.risk_score,
                "risk_level": s.risk_level,
                "modules_scanned": s.modules_scanned,
                "total_tests": s.total_tests,
                "passed_tests": s.passed_tests,
                "failed_tests": s.failed_tests,
                "findings": findings_data
            }

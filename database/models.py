from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    repository_url = Column(String(255), nullable=False)
    branch = Column(String(100), nullable=False)
    commit_hash = Column(String(40))
    scan_date = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(50), default='pending')  # pending, running, completed, failed
    current_step = Column(String(100))  # cloning, language_detection, codeql_analysis, dependency_check
    progress_percentage = Column(Integer, default=0)
    status_message = Column(Text)  # Detailed status message
    error_message = Column(Text)  # Detailed error message if failed
    
    # Add new fields for parallel task tracking
    codeql_status = Column(String(50), default='pending')  # pending, running, completed, failed
    dependency_status = Column(String(50), default='pending')  # pending, running, completed, failed
    start_time = Column(DateTime)  # Track when scan started for time estimates
    
    codeql_findings = relationship("CodeQLFinding", back_populates="scan")
    dependency_findings = relationship("DependencyCheckFinding", back_populates="scan")

class CodeQLFinding(Base):
    __tablename__ = 'codeql_findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    rule_id = Column(String(255))
    rule_index = Column(Integer)
    message = Column(Text)
    file_path = Column(String(255))
    start_line = Column(Integer)
    start_column = Column(Integer)
    end_column = Column(Integer)
    fingerprint = Column(String(255))
    # LLM analysis fields
    llm_verification = Column(Text)
    llm_exploitability = Column(Text)
    llm_remediation = Column(Text)
    llm_priority = Column(Text)
    raw_data = Column(JSON)
    code_context = Column(Text)
    analysis = Column(JSON)
    
    scan = relationship("Scan", back_populates="codeql_findings")

class DependencyCheckFinding(Base):
    __tablename__ = 'dependency_check_findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    dependency_name = Column(String(255))
    dependency_version = Column(String(100))
    vulnerability_id = Column(String(100))
    vulnerability_name = Column(String(255))
    severity = Column(String(50))
    cvss_score = Column(Float)
    description = Column(Text)
    # LLM analysis fields
    llm_exploitability = Column(Text)
    llm_remediation = Column(Text)
    llm_priority = Column(Text)
    raw_data = Column(JSON)
    
    scan = relationship("Scan", back_populates="dependency_findings") 
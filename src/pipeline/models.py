from dataclasses import dataclass, field
from typing import Optional

@dataclass
class AtomicTest:
    technique: str
    test_number: int 

@dataclass
class Alert:
    name: str
    reason: dict

@dataclass
class TestResult:
    technique: str
    test_number: int
    alerts: list[Alert] = field(default_factory=list)
    has_rule: bool = True 
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    status: str = "pending" # failed, no rules, detected, not detected

@dataclass
class RuleMapping:
    by_technique: dict[str, list[str]]

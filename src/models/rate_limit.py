from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from enum import Enum


class RateLimitType(str, Enum):
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    GOOGLE_ADAPTIVE = "google_adaptive"


class RateLimitConfig(BaseModel):
    """Configuration for a rate limit rule"""
    key_prefix: str
    max_requests: int
    window_seconds: int
    type: RateLimitType = RateLimitType.SLIDING_WINDOW
    burst_allowance: Optional[int] = None  # For token bucket
    refill_rate: Optional[int] = None  # For token bucket


class RateLimitResult(BaseModel):
    """Result of a rate limit check"""
    allowed: bool
    remaining: int
    reset_time: int
    limit: int
    retry_after: Optional[int] = None


class RateLimitStats(BaseModel):
    """Statistics for monitoring"""
    total_requests: int
    blocked_requests: int
    average_response_time: float
    key_usage: Dict[str, int]
    time_window: str


class AbuseAlert(BaseModel):
    """Alert data for webhook notifications"""
    alert_type: str
    identifier: str
    threshold_breached: int
    current_count: int
    time_window: int
    metadata: Dict[str, Any] = {}


class BotAnalysis(BaseModel):
    """Bot detection analysis result"""
    score: int
    signals: Dict[str, Any]
    classification: str  # 'legitimate', 'suspicious', 'challenge', 'block'
    recommendation: str  # 'allow', 'monitor', 'challenge', 'block'


class Challenge(BaseModel):
    """Proof-of-work challenge"""
    id: str
    timestamp: int
    difficulty: int
    type: str
    expires: int


class ChallengeResponse(BaseModel):
    """Response to a challenge"""
    challenge_id: str
    nonce: str


class ChallengeVerification(BaseModel):
    """Challenge verification result"""
    verified: bool
    message: str


class Zone(BaseModel):
    """Security zone for multi-tenant protection"""
    id: str
    name: str
    owner: str
    api_key: str
    created_at: int
    status: str = "active"  # active, suspended, deleted
    description: Optional[str] = None


class ZoneConfig(BaseModel):
    """Per-zone security configuration"""
    zone_id: str
    version: int = 1
    updated_at: int

    # Bot protection settings
    bot_protection: Dict[str, Any] = {
        "enabled": True,
        "suspicious_threshold": 30,
        "challenge_threshold": 50,
        "block_threshold": 70,
        "challenge_level": "medium"
    }

    # Rate limiting settings
    rate_limit: Dict[str, Any] = {
        "enabled": True,
        "requests": 100,
        "per_seconds": 60,
        "burst_allowance": 20
    }

    # Challenge settings
    challenge: Dict[str, Any] = {
        "pow_difficulty": 2,
        "timeout_seconds": 300,
        "trust_ttl_seconds": 3600
    }

    # WAF settings
    waf: Dict[str, Any] = {
        "enabled": False,
        "rules": []
    }


class SecurityRule(BaseModel):
    """WAF-style security rule"""
    id: str
    zone_id: str
    name: str
    description: str
    priority: int  # Higher number = higher priority
    enabled: bool = True
    created_at: int
    updated_at: int

    # Conditions (IF)
    conditions: List[Dict[str, Any]] = []

    # Actions (THEN)
    actions: List[Dict[str, Any]] = []

    # Statistics
    hit_count: int = 0
    last_hit: Optional[int] = None


class RuleCondition(BaseModel):
    """Individual rule condition"""
    field: str  # path, method, ip, user_agent, bot_score, headers, etc.
    operator: str  # equals, contains, greater_than, less_than, regex, etc.
    value: Any
    case_sensitive: bool = False


class RuleAction(BaseModel):
    """Individual rule action"""
    type: str  # allow, block, challenge, rate_limit, log
    parameters: Dict[str, Any] = {}


class ZoneAnalytics(BaseModel):
    """Zone analytics and statistics"""
    zone_id: str
    time_range: str  # 1h, 24h, 7d, 30d

    # Traffic stats
    total_requests: int = 0
    blocked_requests: int = 0
    challenged_requests: int = 0
    human_traffic: int = 0
    bot_traffic: int = 0

    # Top data
    top_ips: List[Dict[str, Any]] = []
    top_paths: List[Dict[str, Any]] = []
    top_user_agents: List[Dict[str, Any]] = []

    # Bot analysis
    bot_score_distribution: Dict[str, int] = {}
    challenge_success_rate: float = 0.0

    # Rule performance
    rule_hits: List[Dict[str, Any]] = []


class User(BaseModel):
    """User account for multi-tenant access"""
    id: str
    email: str
    name: str
    role: str  # owner, admin, analyst, viewer
    zones: List[str] = []  # Zone IDs this user can access
    created_at: int
    last_login: Optional[int] = None
    api_key: str


class SecurityEvent(BaseModel):
    """Security event for alerts and logging"""
    id: str
    zone_id: str
    event_type: str  # bot_spike, ddos_suspected, rule_spike, challenge_flood
    severity: str  # low, medium, high, critical
    timestamp: int
    details: Dict[str, Any]
    resolved: bool = False
    resolved_at: Optional[int] = None


class User(BaseModel):
    """User account for dashboard access"""
    id: str
    email: str
    name: str
    avatar: Optional[str] = None
    provider: str  # 'google', 'email'
    provider_id: str
    role: str = "user"  # user, admin, super_admin
    zones: List[str] = []  # Zone IDs this user can access
    created_at: int
    last_login: Optional[int] = None
    is_active: bool = True
    email_verified: bool = False


class UserSession(BaseModel):
    """User session for authentication"""
    id: str
    user_id: str
    token: str
    expires_at: int
    created_at: int
    ip_address: str
    user_agent: str


class AuthRequest(BaseModel):
    """Authentication request"""
    email: str
    password: Optional[str] = None
    provider: str = "email"  # 'google', 'email'
    provider_id: Optional[str] = None  # OAuth provider ID
    name: Optional[str] = None  # User display name


class AuthResponse(BaseModel):
    """Authentication response"""
    user: User
    session: UserSession
    redirect_url: str = "/dashboard"
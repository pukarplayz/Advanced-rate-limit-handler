from pydantic_settings import BaseSettings
from typing import Optional, List
import os


class Settings(BaseSettings):
    # Application settings
    app_name: str = "SentinelEdge"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # Redis settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_max_connections: int = 20

    # Rate limiting defaults
    default_window_seconds: int = 60
    default_max_requests: int = 100

    # Security settings
    secret_key: str = "43b15b7ab3f9e281def2c3834cfc6d7454cef130464f8f4566a0b3af3c7a1b28"
    allowed_hosts: List[str] = []

    # Webhook settings for alerts
    webhook_url: Optional[str] = None
    webhook_timeout: int = 5

    # Dashboard settings
    enable_dashboard: bool = True
    dashboard_username: str = "admin"
    dashboard_password: str = "admin123"  # Change in production!

    # Authentication settings
    google_oauth_client_id: Optional[str] = "1036553636806-7lsm2rir4cclf8plc2l40j8abimh3umn.apps.googleusercontent.com"
    google_oauth_client_secret: Optional[str] = "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"
    google_oauth_redirect_uri: str = "http://localhost:8000/auth/google/callback"

    # Google reCAPTCHA settings (integrated as SentinelEdge security)
    recaptcha_site_key: str = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"  # Test key - replace with your production key from Google reCAPTCHA console
    recaptcha_secret_key: str = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"  # Test key - replace with your production secret key

    # JWT settings
    jwt_secret_key: str = "3473268a6a2705379b5c1e47b769269e7434659dc8231d5a17a077b9ef74af3ae6e2d5940bfe0b8a1c296f201bad459ccea25139c004116bfc99c44df490a2e4"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Bot detection settings
    enable_bot_detection: bool = True
    bot_suspicious_threshold: int = 30
    bot_challenge_threshold: int = 50
    bot_block_threshold: int = 70
    challenge_difficulty: int = 2
    challenge_timeout_seconds: int = 300  # 5 minutes
    verification_trust_seconds: int = 3600  # 1 hour

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse
import time
from ..services.bot_detector import BotDetector
from ..models.rate_limit import Challenge, ChallengeResponse, ChallengeVerification
from pydantic import BaseModel
import httpx
from ..core.config import settings

class CaptchaVerificationRequest(BaseModel):
    challenge_id: str
    nonce: str

class GoogleRecaptchaResponse(BaseModel):
    success: bool
    challenge_ts: str = None
    hostname: str = None
    error_codes: list = None

class AICaptchaVerificationRequest(BaseModel):
    challenges_completed: int
    timestamp: int

router = APIRouter(prefix="/challenge", tags=["challenges"])


@router.post("/generate", response_model=Challenge)
async def generate_challenge(request: Request):
    """Generate a proof-of-work challenge"""
    detector = request.app.state.bot_detector
    challenge_data = await detector.generate_challenge(request)
    return Challenge(**challenge_data)


@router.post("/verify", response_model=ChallengeVerification)
async def verify_challenge(
    response: ChallengeResponse,
    request: Request
):
    """Verify a completed challenge"""
    detector = request.app.state.bot_detector
    verified = await detector.verify_challenge(response.challenge_id, response.nonce)

    if verified:
        return ChallengeVerification(verified=True, message="Challenge passed successfully")
    else:
        return ChallengeVerification(verified=False, message="Challenge verification failed")


@router.post("/dashboard-captcha", response_model=Challenge)
async def generate_dashboard_captcha(request: Request):
    """Generate a CAPTCHA challenge for dashboard access"""
    detector = request.app.state.bot_detector

    # Create a dashboard-specific challenge
    challenge_data = {
        "id": f"dashboard_{int(time.time())}_{hash(str(request.client)) % 10000}",
        "timestamp": int(time.time()),
        "difficulty": 2,  # Medium difficulty for dashboard
        "type": "dashboard_captcha",
        "expires": int(time.time()) + 300  # 5 minutes
    }

    return Challenge(**challenge_data)


@router.post("/dashboard-captcha/verify")
async def verify_dashboard_captcha(
    challenge_id: str = Form(...),
    nonce: str = Form(...)
):
    """Verify dashboard CAPTCHA completion"""
    try:
        # For now, simulate verification - in production this would verify proof-of-work
        # TODO: Implement actual proof-of-work verification
        if challenge_id.startswith("dashboard_") and nonce:
            return {
                "verified": True,
                "message": "Dashboard access granted",
                "trust_token": f"dashboard_{challenge_id}_{int(time.time())}"
            }

        return {
            "verified": False,
            "message": "Invalid challenge parameters"
        }
    except Exception as e:
        return {
            "verified": False,
            "message": f"Verification error: {str(e)}"
        }


@router.post("/recaptcha/verify")
async def verify_google_recaptcha(
    recaptcha_response: str = Form(..., alias="g-recaptcha-response"),
    remote_ip: str = None
):
    """Verify Google reCAPTCHA response"""
    try:
        # Get reCAPTCHA secret from settings (you'll need to add this to config)
        secret_key = getattr(settings, 'recaptcha_secret_key', None)

        if not secret_key:
            # Fallback for demo - in production you'd configure this
            return {
                "verified": True,
                "message": "reCAPTCHA verification bypassed (demo mode)"
            }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": secret_key,
                    "response": recaptcha_response,
                    "remoteip": remote_ip
                }
            )

            result = response.json()

            if result.get("success"):
                return {
                    "verified": True,
                    "message": "Security verification successful",
                    "trust_token": f"sentinel_{int(time.time())}_{hash(recaptcha_response) % 10000}"
                }
            else:
                return {
                    "verified": False,
                    "message": "Security verification failed",
                    "error_codes": result.get("error-codes", [])
                }

    except Exception as e:
        return {
            "verified": False,
            "message": f"Security verification error: {str(e)}"
        }


@router.post("/ai-captcha/verify")
async def verify_ai_captcha(request_data: dict):
    """Verify AI-based CAPTCHA completion"""
    try:
        # Extract and validate data
        challenges_completed = request_data.get("challenges_completed", 0)
        timestamp = request_data.get("timestamp", 0)

        # Ensure proper types
        challenges_completed = int(challenges_completed)
        timestamp = int(timestamp)

        # Verify that the user completed the required number of challenges
        if challenges_completed < 3:
            raise HTTPException(status_code=400, detail="Insufficient challenges completed")

        # Verify timestamp is reasonable (within last 10 minutes for testing)
        current_time = int(time.time() * 1000)
        if abs(current_time - timestamp) > 600000:  # 10 minutes in milliseconds
            raise HTTPException(status_code=400, detail="Challenge session expired")

        # Generate a trust token for the verified user
        trust_token = f"sentinel_ai_{int(time.time())}_{hash(str(timestamp)) % 10000}"

        return {
            "verified": True,
            "message": "AI security verification successful",
            "trust_token": trust_token
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI CAPTCHA verification error: {e}")
        raise HTTPException(status_code=500, detail="Verification failed")


@router.post("/rate-limit-captcha")
async def generate_rate_limit_captcha(request: Request):
    """Generate a CAPTCHA challenge for rate-limited API requests"""
    detector = request.app.state.bot_detector

    # Create a rate-limit specific challenge
    challenge_data = {
        "id": f"rate_limit_{int(time.time())}_{hash(str(request.client)) % 10000}",
        "timestamp": int(time.time()),
        "difficulty": 3,  # Higher difficulty for rate limit violations
        "type": "rate_limit_captcha",
        "expires": int(time.time()) + 300,  # 5 minutes
        "reason": "rate_limit_exceeded",
        "message": "Too many requests detected. Complete this challenge to continue."
    }

    return Challenge(**challenge_data)


@router.post("/rate-limit-captcha/verify")
async def verify_rate_limit_captcha(
    challenge_id: str,
    nonce: str,
    request: Request
):
    """Verify rate-limit CAPTCHA completion"""
    detector = request.app.state.bot_detector

    # For demo purposes, simulate verification
    # In production, this would verify actual proof-of-work
    if challenge_id.startswith("rate_limit_") and nonce:
        # Generate a temporary trust token
        trust_token = f"trust_{challenge_id}_{int(time.time())}"

        return {
            "verified": True,
            "message": "CAPTCHA verified. Access restored.",
            "trust_token": trust_token,
            "trust_expires": int(time.time()) + 3600  # 1 hour trust
        }

    return {
        "verified": False,
        "message": "CAPTCHA verification failed. Please try again.",
        "error": "invalid_challenge"
    }


@router.get("/dashboard-captcha-page", response_class=HTMLResponse)
async def dashboard_captcha_page():
    """Serve the dashboard CAPTCHA challenge page"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Verification - SentinelEdge</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #0A1929 0%, #1E3A8A 100%);
                color: #FFFFFF;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }

            .captcha-container {
                background: rgba(15, 23, 42, 0.95);
                backdrop-filter: blur(20px);
                border-radius: 20px;
                border: 1px solid rgba(255, 107, 53, 0.3);
                padding: 40px;
                max-width: 600px;
                width: 100%;
                box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3);
                animation: slideUp 0.5s ease-out;
            }

            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            .captcha-header {
                text-align: center;
                margin-bottom: 30px;
            }

            .logo-section {
                margin-bottom: 20px;
            }

            .shield-icon {
                width: 70px;
                height: 70px;
                background: linear-gradient(135deg, #FF6B35, #E55A2B);
                border-radius: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 28px;
                margin: 0 auto 15px;
                animation: pulse 2s ease-in-out infinite;
            }

            @keyframes pulse {
                0%, 100% {
                    transform: scale(1);
                }
                50% {
                    transform: scale(1.05);
                }
            }

            .logo-text {
                font-size: 24px;
                font-weight: bold;
                color: #FF6B35;
                margin-bottom: 10px;
            }

            .subtitle {
                color: #CBD5E1;
                font-size: 16px;
            }

            .challenge-section {
                background: rgba(30, 41, 59, 0.8);
                border-radius: 12px;
                padding: 25px;
                margin-bottom: 25px;
                border: 1px solid rgba(255, 107, 53, 0.2);
            }

            .challenge-title {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 15px;
                font-size: 18px;
                font-weight: 600;
            }

            .challenge-title i {
                color: #00D4FF;
            }

            .progress-container {
                margin-bottom: 20px;
            }

            .progress-bar {
                height: 8px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 4px;
                overflow: hidden;
                margin-bottom: 10px;
            }

            .progress-fill {
                height: 100%;
                background: linear-gradient(90deg, #00D4FF, #8B5CF6, #EC4899);
                background-size: 200% 100%;
                animation: progress 2s ease-in-out infinite;
                width: 0%;
                transition: width 0.3s ease;
            }

            @keyframes progress {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }

            .progress-text {
                text-align: center;
                font-size: 14px;
                color: #00D4FF;
                font-weight: 500;
            }

            .challenge-description {
                color: #CBD5E1;
                margin-bottom: 20px;
                line-height: 1.5;
            }

            .action-buttons {
                display: flex;
                gap: 15px;
                justify-content: center;
                flex-wrap: wrap;
            }

            .btn {
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s ease;
                border: none;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                text-decoration: none;
            }

            .btn-primary {
                background: linear-gradient(135deg, #10B981, #059669);
                color: white;
            }

            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
            }

            .btn-secondary {
                background: rgba(255, 255, 255, 0.1);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 0.3);
            }

            .btn-secondary:hover {
                background: rgba(255, 255, 255, 0.2);
                border-color: rgba(255, 255, 255, 0.5);
            }

            .info-section {
                background: rgba(59, 130, 246, 0.1);
                border: 1px solid rgba(59, 130, 246, 0.3);
                border-radius: 8px;
                padding: 20px;
            }

            .info-section h3 {
                color: #3B82F6;
                margin-bottom: 10px;
                font-size: 16px;
            }

            .info-section p {
                color: #BFDBFE;
                font-size: 14px;
                line-height: 1.5;
            }

            @media (max-width: 640px) {
                .captcha-container {
                    padding: 20px;
                    margin: 10px;
                }

                .action-buttons {
                    flex-direction: column;
                }

                .btn {
                    width: 100%;
                    justify-content: center;
                }
            }
        </style>
    </head>
    <body>
        <div class="captcha-container">
            <div class="captcha-header">
                <div class="logo-section">
                    <div class="shield-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div class="logo-text">SentinelEdge</div>
                    <div class="subtitle">Security Verification</div>
                </div>
            </div>

            <div class="challenge-section">
                <div class="challenge-title">
                    <i class="fas fa-shield-alt"></i>
                    <span>Security Verification</span>
                </div>

                <div class="challenge-description">
                    Complete the verification to access your dashboard and API services.
                </div>

                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" id="challenge-progress"></div>
                    </div>
                    <div class="progress-text" id="progress-text">Ready to start</div>
                </div>

                <div class="action-buttons">
                    <button class="btn btn-primary" id="start-challenge">
                        <i class="fas fa-play"></i>
                        <span>Start Verification</span>
                    </button>
                    <a href="/" class="btn btn-secondary">
                        <i class="fas fa-home"></i>
                        <span>Back to Home</span>
                    </a>
                </div>
            </div>

            <div class="info-section">
                <h3><i class="fas fa-info-circle"></i> Why this verification?</h3>
                <p>This helps protect our services from automated abuse and ensures fair access for all users. The process is quick and secure.</p>
            </div>
        </div>

        <script>
            let progressInterval;
            let currentProgress = 0;

            document.getElementById('start-challenge').addEventListener('click', async () => {
                const button = document.getElementById('start-challenge');
                const progressBar = document.getElementById('challenge-progress');
                const progressText = document.getElementById('progress-text');

                // Disable button
                button.disabled = true;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Verifying...</span>';

                try {
                    // For demo purposes, simulate verification progress
                // In production, this would be handled by the reCAPTCHA callback
                progressInterval = setInterval(() => {
                    currentProgress += Math.random() * 5;
                    if (currentProgress > 100) currentProgress = 100;

                    progressBar.style.width = currentProgress + '%';
                    progressText.textContent = Math.round(currentProgress) + '% Complete';

                    if (currentProgress >= 100) {
                        clearInterval(progressInterval);
                        completeChallenge();
                    }
                }, 200);

                } catch (error) {
                    console.error('Challenge failed:', error);
                    progressText.textContent = 'Verification failed - please try again';
                    progressText.style.color = '#EF4444';
                    button.disabled = false;
                    button.innerHTML = '<i class="fas fa-redo"></i><span>Try Again</span>';
                }
            });

            async function completeChallenge() {
                try {
                    // Verify challenge (simulated)
                    const verifyResponse = await fetch('/challenge/dashboard-captcha/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            challenge_id: 'dashboard_' + Date.now(),
                            nonce: 'verified_' + Date.now()
                        })
                    });

                    if (verifyResponse.ok) {
                        // Success - redirect to dashboard
                        window.location.href = '/dashboard';
                    } else {
                        throw new Error('Verification failed');
                    }
                } catch (error) {
                    console.error('Verification failed:', error);
                    document.getElementById('progress-text').textContent = 'Verification failed';
                    document.getElementById('progress-text').style.color = '#EF4444';
                }
            }
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


@router.get("/rate-limit-page", response_class=HTMLResponse)
async def rate_limit_challenge_page(request: Request):
    """Serve a rate limit challenge page for API requests"""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get('user-agent', 'unknown')

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rate Limit Exceeded - SentinelEdge</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #0A1929 0%, #1E3A8A 100%);
                color: #FFFFFF;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}

            .challenge-container {{
                background: rgba(15, 23, 42, 0.95);
                backdrop-filter: blur(20px);
                border-radius: 16px;
                border: 1px solid rgba(255, 107, 53, 0.3);
                padding: 40px;
                max-width: 500px;
                width: 100%;
                text-align: center;
                box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3);
            }}

            .logo {{
                margin-bottom: 30px;
            }}

            .shield-icon {{
                width: 60px;
                height: 60px;
                background: linear-gradient(135deg, #FF6B35, #E55A2B);
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 24px;
                margin: 0 auto 20px;
            }}

            .logo-text {{
                font-size: 20px;
                font-weight: bold;
                color: #FF6B35;
            }}

            .challenge-title {{
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 10px;
                color: #FFFFFF;
            }}

            .challenge-subtitle {{
                color: #CBD5E1;
                margin-bottom: 30px;
                line-height: 1.6;
            }}

            .rate-limit-info {{
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 30px;
            }}

            .rate-limit-info h3 {{
                color: #EF4444;
                margin-bottom: 10px;
                font-size: 18px;
            }}

            .rate-limit-info p {{
                color: #FCA5A5;
                font-size: 14px;
                line-height: 1.5;
            }}

            .challenge-actions {{
                display: flex;
                gap: 15px;
                justify-content: center;
                flex-wrap: wrap;
            }}

            .btn {{
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s ease;
                border: none;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }}

            .btn-primary {{
                background: linear-gradient(135deg, #10B981, #059669);
                color: white;
            }}

            .btn-primary:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
            }}

            .btn-secondary {{
                background: rgba(255, 255, 255, 0.1);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 0.3);
            }}

            .btn-secondary:hover {{
                background: rgba(255, 255, 255, 0.2);
                border-color: rgba(255, 255, 255, 0.5);
            }}

            .request-info {{
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }}

            .request-info h4 {{
                color: #CBD5E1;
                margin-bottom: 10px;
                font-size: 14px;
            }}

            .info-item {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 5px;
                font-size: 12px;
                color: #94A3B8;
            }}

            .info-label {{
                font-weight: 500;
            }}

            .info-value {{
                font-family: 'Monaco', 'Menlo', monospace;
                color: #CBD5E1;
            }}
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <div class="logo">
                <div class="shield-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <div class="logo-text">SentinelEdge</div>
            </div>

            <div class="challenge-title">Rate Limit Exceeded</div>
            <div class="challenge-subtitle">
                You've made too many requests too quickly. Complete the security verification to continue.
            </div>

            <div class="rate-limit-info">
                <h3><i class="fas fa-shield-alt"></i> Rate Limit Exceeded</h3>
                <p>Your request has been temporarily blocked due to excessive API usage. Complete the verification below to continue.</p>
            </div>

            <div class="challenge-actions">
                <a href="/challenge/dashboard-captcha-page" class="btn btn-primary">
                    <i class="fas fa-robot"></i>
                    Complete Verification
                </a>
                <a href="/" class="btn btn-secondary">
                    <i class="fas fa-home"></i>
                    Back to Home
                </a>
            </div>

            <div class="request-info">
                <h4>Request Information</h4>
                <div class="info-item">
                    <span class="info-label">IP Address:</span>
                    <span class="info-value">{client_ip}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">User Agent:</span>
                    <span class="info-value">{user_agent[:50]}{'...' if len(user_agent) > 50 else ''}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Timestamp:</span>
                    <span class="info-value">{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}</span>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


@router.get("/page/{challenge_id}", response_class=HTMLResponse)
async def challenge_page(challenge_id: str):
    """Serve a challenge page for browser-based verification"""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Challenge</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
            }}
            .challenge-container {{
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 2rem;
                text-align: center;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                max-width: 500px;
                width: 90%;
            }}
            .spinner {{
                border: 4px solid rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                border-top: 4px solid white;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            .status {{
                margin-top: 20px;
                font-size: 1.2rem;
            }}
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <h1>🔒 Security Challenge</h1>
            <p>Verifying your request...</p>
            <div class="spinner"></div>
            <div class="status" id="status">Solving challenge...</div>
        </div>

        <script>
            const challengeId = '{challenge_id}';
            let startTime = Date.now();

            async function solveChallenge() {{
                const target = challengeId;
                let nonce = 0;
                const difficulty = {settings.challenge_difficulty}; // Match server difficulty

                while (true) {{
                    const hash = await crypto.subtle.digest(
                        'SHA-256',
                        new TextEncoder().encode(target + nonce.toString())
                    );
                    const hashArray = new Uint8Array(hash);
                    const hashHex = Array.from(hashArray)
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');

                    if (hashHex.startsWith('0'.repeat(difficulty))) {{
                        return nonce.toString();
                    }}

                    nonce++;

                    // Update status every 1000 attempts
                    if (nonce % 1000 === 0) {{
                        document.getElementById('status').textContent =
                            `Solving challenge... (${{nonce}} attempts)`;
                    }}
                }}
            }}

            async function verifyChallenge(nonce) {{
                try {{
                    const response = await fetch('/challenge/verify', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            challenge_id: challengeId,
                            nonce: nonce
                        }})
                    }});

                    const result = await response.json();

                    if (result.verified) {{
                        document.getElementById('status').textContent = '✓ Challenge completed! Redirecting...';
                        setTimeout(() => {{
                            window.location.href = '/';
                        }}, 2000);
                    }} else {{
                        document.getElementById('status').textContent = '✗ Challenge failed. Please try again.';
                    }}
                }} catch (error) {{
                    document.getElementById('status').textContent = 'Error verifying challenge.';
                    console.error('Verification error:', error);
                }}
            }}

            // Start solving the challenge
            solveChallenge().then(verifyChallenge);
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content, status_code=200)


@router.get("/stats")
async def challenge_stats(request: Request):
    """Get challenge statistics"""
    detector = request.app.state.bot_detector

    # This would track challenge success/failure rates
    # For now, return placeholder stats
    return {
        "total_challenges": 0,
        "successful_verifications": 0,
        "failed_attempts": 0,
        "average_solve_time": 0
    }
import re
import time
import hashlib
import secrets
import string
from typing import Dict, Any, Optional, Tuple
from fastapi import Request
from ..core.redis_client import redis_client
from ..core.config import settings
import logging

logger = logging.getLogger(__name__)


class BotDetector:
    """Advanced bot detection and challenge system"""

    def __init__(self):
        self.redis = redis_client
        # Bot scoring thresholds from config
        self.suspicious_threshold = settings.bot_suspicious_threshold
        self.block_threshold = settings.bot_block_threshold
        self.challenge_threshold = settings.bot_challenge_threshold

        # Known bot patterns
        self.bot_user_agents = [
            r'bot', r'crawler', r'spider', r'scraper', r'headless',
            r'python-requests', r'curl', r'wget', r'go-http-client'
        ]

        # Legitimate browser patterns
        self.browser_patterns = [
            r'chrome', r'firefox', r'safari', r'edge', r'opera',
            r'mozilla', r'mobile safari'
        ]

    async def analyze_request(self, request: Request) -> Dict[str, Any]:
        """Analyze a request and return bot score and signals"""
        signals = {}
        score = 0

        # User-Agent analysis
        ua_score, ua_signals = self._analyze_user_agent(request.headers.get('user-agent', ''))
        score += ua_score
        signals.update(ua_signals)

        # Header consistency analysis
        header_score, header_signals = self._analyze_headers(request)
        score += header_score
        signals.update(header_signals)

        # Request timing patterns (would need session tracking)
        timing_score, timing_signals = await self._analyze_timing_patterns(request)
        score += timing_score
        signals.update(timing_signals)

        # IP reputation
        ip_score, ip_signals = await self._analyze_ip_reputation(self._get_client_ip(request))
        score += ip_score
        signals.update(ip_signals)

        # Request frequency patterns
        freq_score, freq_signals = await self._analyze_request_frequency(request)
        score += freq_score
        signals.update(freq_signals)

        # Normalize score to 0-100
        final_score = min(100, max(0, score))

        return {
            'score': final_score,
            'signals': signals,
            'classification': self._classify_score(final_score),
            'recommendation': self._get_recommendation(final_score)
        }

    def _analyze_user_agent(self, user_agent: str) -> Tuple[int, Dict[str, Any]]:
        """Analyze User-Agent string for bot signals"""
        if not user_agent:
            return 50, {'user_agent': {'missing': True, 'suspicious': True}}

        ua_lower = user_agent.lower()
        signals = {'user_agent': {'value': user_agent[:100]}}  # Truncate for storage
        score = 0

        # Check for known bot patterns
        bot_matches = []
        for pattern in self.bot_user_agents:
            if re.search(pattern, ua_lower, re.IGNORECASE):
                bot_matches.append(pattern)
                score += 15

        if bot_matches:
            signals['user_agent']['bot_patterns'] = bot_matches

        # Check for browser patterns (reduce suspicion)
        browser_matches = []
        for pattern in self.browser_patterns:
            if re.search(pattern, ua_lower, re.IGNORECASE):
                browser_matches.append(pattern)
                score -= 10

        if browser_matches:
            signals['user_agent']['browser_patterns'] = browser_matches

        # Entropy analysis (bots often have low entropy)
        entropy = self._calculate_entropy(user_agent)
        if entropy < 3.0:
            score += 20
            signals['user_agent']['low_entropy'] = True

        # Length analysis
        if len(user_agent) < 20:
            score += 10
            signals['user_agent']['too_short'] = True
        elif len(user_agent) > 500:
            score += 5
            signals['user_agent']['unusually_long'] = True

        return score, signals

    def _analyze_headers(self, request: Request) -> Tuple[int, Dict[str, Any]]:
        """Analyze HTTP headers for consistency and legitimacy"""
        headers = dict(request.headers)
        signals = {}
        score = 0

        # Check for missing common browser headers
        essential_headers = ['accept', 'accept-language', 'accept-encoding']
        missing_headers = []

        for header in essential_headers:
            if header not in [h.lower() for h in headers.keys()]:
                missing_headers.append(header)
                score += 8

        if missing_headers:
            signals['missing_headers'] = missing_headers

        # Check for suspicious header values
        if 'accept' in headers:
            accept = headers['accept'].lower()
            if accept == '*/*':
                score += 5
                signals['generic_accept'] = True

        # Check for bot-specific headers
        bot_headers = ['x-requested-with', 'x-bot-token']
        for header in bot_headers:
            if header in [h.lower() for h in headers.keys()]:
                score += 15
                signals['bot_headers'] = bot_headers

        # Referer analysis
        if 'referer' not in headers and request.url.path not in ['/', '/health']:
            score += 3
            signals['missing_referer'] = True

        return score, signals

    async def _analyze_timing_patterns(self, request: Request) -> Tuple[int, Dict[str, Any]]:
        """Analyze request timing patterns (simplified version)"""
        client_ip = self._get_client_ip(request)
        signals = {}
        score = 0

        try:
            client = await self.redis.connect()
            if client:
                # Store last request time for this IP
                last_request_key = f"last_request:{client_ip}"
                current_time = time.time()

                last_time = await client.get(last_request_key)
                if last_time:
                    time_diff = current_time - float(last_time)
                    if time_diff < 0.1:  # Less than 100ms between requests
                        score += 20
                        signals['rapid_requests'] = True
                    elif time_diff > 300:  # More than 5 minutes, reset
                        await client.delete(last_request_key)

                await client.setex(last_request_key, 300, current_time)  # 5 minute expiry

        except Exception as e:
            logger.warning(f"Failed to analyze timing patterns: {e}")

        return score, signals

    async def _analyze_ip_reputation(self, ip: str) -> Tuple[int, Dict[str, Any]]:
        """Check IP reputation (simplified version)"""
        signals = {}
        score = 0

        # This would integrate with IP reputation databases
        # For now, just check if IP has been flagged before
        try:
            client = await self.redis.connect()
            if client:
                reputation_key = f"ip_reputation:{ip}"
                reputation = await client.get(reputation_key)

                if reputation:
                    rep_score = int(reputation)
                    score += rep_score
                    signals['ip_reputation'] = rep_score

        except Exception as e:
            logger.warning(f"Failed to check IP reputation: {e}")

        return score, signals

    async def _analyze_request_frequency(self, request: Request) -> Tuple[int, Dict[str, Any]]:
        """Analyze request frequency patterns"""
        client_ip = self._get_client_ip(request)
        signals = {}
        score = 0

        try:
            client = await self.redis.connect()
            if client:
                # Count requests in last minute
                minute_key = f"requests_minute:{client_ip}:{int(time.time() // 60)}"
                count = await client.incr(minute_key)
                await client.expire(minute_key, 120)  # 2 minutes

                if count > 30:  # More than 30 requests per minute
                    score += 25
                    signals['high_frequency'] = count

        except Exception as e:
            logger.warning(f"Failed to analyze request frequency: {e}")

        return score, signals

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0

        entropy = 0
        text_length = len(text)

        for char in set(text):
            p = text.count(char) / text_length
            if p > 0:
                entropy -= p * (p.log2() if hasattr(p, 'log2') else __import__('math').log2(p))

        return entropy

    def _classify_score(self, score: int) -> str:
        """Classify bot score"""
        if score >= self.block_threshold:
            return 'block'
        elif score >= self.challenge_threshold:
            return 'challenge'
        elif score >= self.suspicious_threshold:
            return 'suspicious'
        else:
            return 'legitimate'

    def _get_recommendation(self, score: int) -> str:
        """Get action recommendation based on score"""
        if score >= self.block_threshold:
            return 'block'
        elif score >= self.challenge_threshold:
            return 'challenge'
        elif score >= self.suspicious_threshold:
            return 'monitor'
        else:
            return 'allow'

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address"""
        headers_to_check = [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "X-Client-IP"
        ]

        for header in headers_to_check:
            ip = request.headers.get(header)
            if ip:
                return ip.split(",")[0].strip()

        return request.client.host if request.client else "unknown"

    async def generate_challenge(self, request: Request, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate a proof-of-work challenge"""
        client_ip = self._get_client_ip(request)
        challenge_id = secrets.token_hex(16)
        timestamp = int(time.time())

        # Create a simple proof-of-work challenge
        # Client must find a nonce such that hash(nonce + challenge_id) starts with required zeros
        difficulty = config.get('pow_difficulty', settings.challenge_difficulty) if config else settings.challenge_difficulty
        timeout = config.get('timeout_seconds', settings.challenge_timeout_seconds) if config else settings.challenge_timeout_seconds

        challenge_data = {
            'id': challenge_id,
            'timestamp': timestamp,
            'difficulty': difficulty,
            'type': 'pow',
            'expires': timestamp + timeout,
            'client_ip': client_ip  # Store IP for verification
        }

        # Store challenge in Redis
        try:
            client = await self.redis.connect()
            if client:
                challenge_key = f"challenge:{challenge_id}"
                await client.setex(challenge_key, 300, str(challenge_data))
        except Exception as e:
            logger.error(f"Failed to store challenge: {e}")

        return challenge_data

    async def verify_challenge(self, challenge_id: str, nonce: str) -> bool:
        """Verify a completed challenge"""
        try:
            client = await self.redis.connect()
            if not client:
                return False

            challenge_key = f"challenge:{challenge_id}"
            challenge_data_str = await client.get(challenge_key)

            if not challenge_data_str:
                return False

            # Parse challenge data
            challenge_data = eval(challenge_data_str)  # In production, use JSON

            # Check if challenge has expired
            if time.time() > challenge_data['expires']:
                return False

            # Verify proof-of-work
            target = challenge_data['id'] + nonce
            hash_result = hashlib.sha256(target.encode()).hexdigest()

            # Check if hash starts with required number of zeros
            required_zeros = challenge_data['difficulty']
            if hash_result.startswith('0' * required_zeros):
                # Challenge passed - mark as verified
                verified_key = f"verified:{self._get_client_ip_from_challenge(challenge_data)}"
                await client.setex(verified_key, settings.verification_trust_seconds, 'true')
                return True

        except Exception as e:
            logger.error(f"Failed to verify challenge: {e}")

        return False

    def _get_client_ip_from_challenge(self, challenge_data: Dict) -> str:
        """Extract IP from challenge data"""
        return challenge_data.get('client_ip', 'unknown')

    async def is_verified(self, request: Request) -> bool:
        """Check if client is verified (passed challenge recently)"""
        client_ip = self._get_client_ip(request)

        try:
            client = await self.redis.connect()
            if client:
                verified_key = f"verified:{client_ip}"
                return bool(await client.get(verified_key))
        except Exception:
            pass

        return False
# SentinelEdge  
Enterprise Edge Security Platform

SentinelEdge is a production-ready edge security platform built with FastAPI, Redis, and asynchronous Python. It provides multi-tenant zone protection, advanced bot detection, flexible rate limiting strategies, and real-time monitoring.

The system is designed for performance, scalability, and operational simplicity. It can be deployed for APIs, SaaS platforms, or internal services that require reliable protection against abuse and automated threats.

---

## Overview

SentinelEdge helps you:

- Protect APIs and services from excessive traffic and abuse
- Detect automated bots using behavioral scoring
- Apply multiple rate limiting algorithms
- Manage isolated security zones for different applications
- Monitor traffic and threats in real time
- Update security configurations without restarting services

---

## Key Features

- Multi-tenant zone architecture
- Asynchronous high-performance request handling
- Behavioral bot detection using multiple request signals
- Proof-of-Work challenge mechanism with temporary trust tokens
- Sliding window, token bucket, and fixed window rate limiting
- Webhook alerts for security events
- Built-in dashboard for analytics and monitoring
- Docker-ready deployment
- Per-zone configurable security policies

---

## Architecture

Client Request  
→ FastAPI Application  
→ Security Middleware (Rate Limiting, Bot Detection, Challenges)  
→ Redis (Distributed Counters and State Management)

Redis is used for distributed counters and request tracking, allowing horizontal scalability.

---

## Technology Stack

- Python 3.11+
- FastAPI
- Redis 7+
- Async/Await architecture
- Docker and Docker Compose
- Gunicorn with Uvicorn workers (production)

---

## Getting Started

### Clone the repository

```bash
git clone https://github.com/pukarplayz/Advanced-rate-limit-handler/
cd rate-limit-system
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Start Redis

Using Docker:

```bash
docker run -d -p 6379:6379 redis:7-alpine
```

Or:

```bash
docker-compose up redis -d
```

### Configure environment variables

Copy the example file:

```bash
cp .env.example .env
```

Edit `.env` as needed:

```env
APP_NAME=SentinelEdge
DEBUG=true

REDIS_HOST=localhost
REDIS_PORT=6379

DEFAULT_WINDOW_SECONDS=60
DEFAULT_MAX_REQUESTS=100

DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=change_this_password
```

### Run the application

```bash
python run.py
```

Access:

- Landing Page: http://localhost:8000  
- Dashboard: http://localhost:8000/dashboard  
- API Documentation: http://localhost:8000/docs  

---

## Multi-Tenant Zone System

Each zone represents an isolated security configuration. Zones have independent:

- Rate limiting settings
- Bot detection thresholds
- Challenge parameters
- Analytics tracking

### Create a zone

```bash
curl -X POST http://localhost:8000/zones/ \
  -H "Content-Type: application/json" \
  -d '{"name": "Production API"}'
```

The response includes a unique API key for that zone.

### Send zone-based requests

```bash
curl -H "X-Zone-Key: sk_live_xxx..." \
     http://localhost:8000/api/test
```

Zones operate independently from one another.

---

## Rate Limiting Algorithms

### Sliding Window
Tracks requests across a rolling time window.  
Provides accurate enforcement for APIs requiring strict control.

### Token Bucket
Accumulates tokens over time and allows controlled bursts.  
Useful for services that experience periodic traffic spikes.

### Fixed Window
Simple time-based window.  
Offers high performance with lower computational overhead.

---

## Bot Detection

SentinelEdge evaluates requests using multiple behavioral signals, including:

- User-Agent analysis
- Header consistency checks
- Request timing patterns
- IP-based behavior scoring
- Request frequency monitoring

Based on scoring thresholds:

- Suspicious traffic can be challenged
- High-risk traffic can be blocked
- Verified clients receive temporary trust tokens

---

## Dashboard

The built-in dashboard provides:

- Real-time traffic statistics
- Zone-level analytics
- Bot detection metrics
- Challenge completion tracking
- Redis connection monitoring

Configuration changes are applied without restarting the service.

---

## Webhook Alerts

Webhook notifications can be configured for:

- Rate limit violations
- Bot detection triggers
- Challenge events
- Security threshold breaches

Example payload:

```json
{
  "alert_type": "rate_limit_exceeded",
  "identifier": "ip:192.168.1.100",
  "current_count": 150
}
```

---

## Docker Deployment

Using Docker Compose:

```bash
docker-compose up --build
```

Manual build:

```bash
docker build -t sentineledge .
docker run -p 8000:8000 --env-file .env sentineledge
```

---

## Production Deployment

Run with Gunicorn:

```bash
gunicorn src.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

Recommended production practices:

- Use HTTPS
- Change default credentials
- Configure CORS policies
- Enable monitoring and structured logging
- Use Redis clustering for high availability

---

## Testing

Run unit tests:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=src --cov-report=html
```

Load testing:

```bash
pip install locust
locust -f tests/load_test.py
```

---

## Performance

- 10,000+ requests per second on moderate hardware
- Average rate limit check latency under 2ms
- Horizontally scalable with Redis
- Optimized Redis memory usage

---

## Contributing

1. Fork the repository  
2. Create a feature branch  
3. Add tests for new functionality  
4. Ensure tests pass  
5. Submit a pull request  

---

## License

MIT License

---

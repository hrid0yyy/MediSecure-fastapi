# 🛡️ Malicious Activity Detection & Auto-Blocking System

## Overview
Automated security threat detection system that monitors login attempts, detects suspicious patterns, automatically blocks malicious IPs, and notifies admins in real-time.

## 🔥 Features

### 1. **Real-time Threat Detection**
- Monitors all login attempts across the system
- Detects multiple attack patterns automatically
- Uses Redis for fast, distributed tracking

### 2. **Intelligent Detection Rules**

#### Rule #1: Brute Force Detection
- **Threshold**: 5+ failed logins within 60 seconds from same IP
- **Action**: Mark as HIGH threat
- **Auto-block**: After 10 failed attempts
- **Threat Type**: `brute_force`

#### Rule #2: Account Enumeration
- **Threshold**: 3+ different email accounts tried from same IP within 5 minutes
- **Action**: Mark as MEDIUM threat
- **Auto-block**: After 5+ different accounts
- **Threat Type**: `multiple_accounts`

### 3. **Auto-Blocking System**
- Automatically blocks IPs that exceed critical thresholds
- Blocked IPs cannot access ANY API endpoint
- Blocks are logged with reason and threat ID
- Admin can manually unblock if needed

### 4. **Admin Notification System**
- Real-time notifications for HIGH and CRITICAL threats
- Shows threat details, IP, attempted accounts, and block status
- Notifications can be marked as read/unread
- Bulk actions supported (mark all as read)

### 5. **Comprehensive Logging**
- All threats logged to `security_threats` table
- Tracks: IP, threat type, level, attempt count, attempted emails
- Resolution tracking (who resolved, when)
- Full audit trail for compliance

## 🏗️ Architecture

### Database Models

#### `security_threats` Table
```python
- id: Primary key
- ip_address: Attacker IP (indexed)
- threat_type: ENUM (failed_login, multiple_accounts, brute_force, etc.)
- threat_level: ENUM (low, medium, high, critical)
- description: Human-readable description
- attempted_emails: JSON array of tried emails
- attempt_count: Number of attempts
- is_blocked: Whether IP was auto-blocked
- is_resolved: Admin marked as resolved
- resolved_by: Admin email who resolved
- resolved_at: Resolution timestamp
- created_at, updated_at
```

#### `admin_notifications` Table
```python
- id: Primary key
- threat_id: Link to security_threat
- title: Notification title
- message: Notification message
- severity: ENUM (low, medium, high, critical)
- is_read: Read status
- read_by: Admin who read it
- read_at: When it was read
- created_at
```

### Service Layer

**`ThreatDetectionService`** (`services/security_service.py`)

Key Methods:
- `track_failed_login()` - Main detection logic
- `_log_threat()` - Record threat to database
- `_auto_block_ip()` - Automatically block malicious IP
- `_create_admin_notification()` - Send alert to admins
- `clear_failed_attempts()` - Clear tracking on successful login
- `get_active_threats()` - Retrieve recent threats

## 📡 API Endpoints (Admin Only)

### Security Threat Monitoring

#### 1. List All Security Threats
```http
GET /api/v1/admin/security-threats
Authorization: Bearer <admin_token>

Query Parameters:
- skip: int (pagination offset, default 0)
- limit: int (max results, default 100)
- threat_level: low|medium|high|critical (filter by severity)
- threat_type: failed_login|multiple_accounts|brute_force (filter by type)
- is_resolved: boolean (show resolved/unresolved only)
- hours: int (1-168, show threats from last N hours, default 24)
```

**Response:**
```json
{
  "total": 15,
  "skip": 0,
  "limit": 100,
  "hours": 24,
  "threats": [
    {
      "id": 1,
      "ip_address": "192.168.1.100",
      "threat_type": "brute_force",
      "threat_level": "critical",
      "description": "Brute force attack detected: 12 failed login attempts within 1 minute",
      "attempted_emails": ["user1@test.com", "admin@test.com"],
      "attempt_count": 12,
      "is_blocked": true,
      "is_resolved": false,
      "resolved_by": null,
      "resolved_at": null,
      "created_at": "2026-01-29T10:30:00",
      "updated_at": "2026-01-29T10:31:00"
    }
  ]
}
```

#### 2. Get Specific Threat Details
```http
GET /api/v1/admin/security-threats/{threat_id}
Authorization: Bearer <admin_token>
```

#### 3. Resolve a Threat
```http
PUT /api/v1/admin/security-threats/{threat_id}/resolve
Authorization: Bearer <admin_token>
```

Marks threat as resolved and records which admin resolved it.

#### 4. Get Threat Statistics
```http
GET /api/v1/admin/security-threats/stats/summary?hours=24
Authorization: Bearer <admin_token>
```

**Response:**
```json
{
  "period_hours": 24,
  "total_threats": 25,
  "auto_blocked_ips": 5,
  "unresolved_threats": 8,
  "by_level": {
    "low": 5,
    "medium": 10,
    "high": 7,
    "critical": 3
  },
  "by_type": {
    "failed_login": 10,
    "brute_force": 8,
    "multiple_accounts": 7
  },
  "top_attacking_ips": [
    {
      "ip_address": "192.168.1.100",
      "threat_count": 5,
      "max_threat_level": "critical"
    }
  ]
}
```

### Admin Notifications

#### 1. List Notifications
```http
GET /api/v1/admin/notifications
Authorization: Bearer <admin_token>

Query Parameters:
- skip: int (default 0)
- limit: int (default 50, max 200)
- is_read: boolean (filter by read status)
- severity: low|medium|high|critical
```

**Response:**
```json
{
  "total": 10,
  "unread_count": 3,
  "skip": 0,
  "limit": 50,
  "notifications": [
    {
      "id": 1,
      "threat_id": 5,
      "title": "🚨 CRITICAL Security Threat Detected",
      "message": "IP 192.168.1.100 detected with brute_force activity. 12 attempts detected and has been AUTO-BLOCKED. Please review immediately.",
      "severity": "critical",
      "is_read": false,
      "read_by": null,
      "read_at": null,
      "created_at": "2026-01-29T10:30:00"
    }
  ]
}
```

#### 2. Mark Notification as Read
```http
PUT /api/v1/admin/notifications/{notification_id}/read
Authorization: Bearer <admin_token>
```

#### 3. Mark All as Read
```http
PUT /api/v1/admin/notifications/read-all
Authorization: Bearer <admin_token>
```

#### 4. Delete Notification
```http
DELETE /api/v1/admin/notifications/{notification_id}
Authorization: Bearer <admin_token>
```

## 🔄 How It Works

### Login Flow with Threat Detection

```
1. User attempts login
   ↓
2. Extract client IP from request headers
   ↓
3. Check if user exists
   ↓
4. Verify password
   ↓
5. IF PASSWORD WRONG:
   → Track failed login in Redis
   → Check detection rules:
     • Count recent failures (last 60 seconds)
     • Count attempted accounts (last 5 minutes)
   → Calculate threat level
   → IF threshold exceeded:
     • Log to security_threats table
     • Auto-block IP if critical
     • Create admin notification
     • Return 403 with block message
   ↓
6. IF PASSWORD CORRECT:
   → Clear failed login tracking
   → Allow login
```

### Detection Algorithm

```python
# Redis Keys Used:
failed_login:{ip_address}     → Sorted set of timestamps
attempted_accounts:{ip_address} → Set of email addresses

# Time Windows:
FAILED_LOGIN_WINDOW = 60 seconds
MULTIPLE_ACCOUNTS_WINDOW = 300 seconds (5 min)

# Detection Logic:
if recent_attempts >= 5:
    threat_level = HIGH
    if recent_attempts >= 10:
        AUTO_BLOCK = True
        threat_level = CRITICAL

if unique_accounts >= 3:
    threat_level = MEDIUM
    if unique_accounts >= 5:
        AUTO_BLOCK = True
```

## 🧪 Testing Guide

### Test Scenario 1: Brute Force Attack
```bash
# Simulate 10 failed login attempts from same IP
for i in {1..10}; do
  curl -X POST "http://localhost:8000/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrongpassword"}'
  echo "Attempt $i"
  sleep 1
done

# After 5 attempts: HIGH threat logged
# After 10 attempts: IP auto-blocked, notification sent
```

### Test Scenario 2: Account Enumeration
```bash
# Try different accounts from same IP
for email in user1 user2 user3 user4 user5; do
  curl -X POST "http://localhost:8000/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${email}@test.com\",\"password\":\"wrong\"}"
done

# After 3 accounts: MEDIUM threat
# After 5 accounts: IP auto-blocked
```

### Test Scenario 3: Check Admin Dashboard
```bash
# Login as admin
TOKEN="<your_admin_token>"

# View threats
curl "http://localhost:8000/api/v1/admin/security-threats" \
  -H "Authorization: Bearer $TOKEN"

# View stats
curl "http://localhost:8000/api/v1/admin/security-threats/stats/summary?hours=1" \
  -H "Authorization: Bearer $TOKEN"

# View notifications
curl "http://localhost:8000/api/v1/admin/notifications" \
  -H "Authorization: Bearer $TOKEN"

# Resolve a threat
curl -X PUT "http://localhost:8000/api/v1/admin/security-threats/1/resolve" \
  -H "Authorization: Bearer $TOKEN"

# Mark notification as read
curl -X PUT "http://localhost:8000/api/v1/admin/notifications/1/read" \
  -H "Authorization: Bearer $TOKEN"
```

## 🔧 Configuration

### Adjust Detection Thresholds

Edit `services/security_service.py`:

```python
# Detection thresholds
FAILED_LOGIN_THRESHOLD = 5      # Increase for less sensitive
FAILED_LOGIN_WINDOW = 60        # Time window (seconds)
MULTIPLE_ACCOUNTS_THRESHOLD = 3  # Account enumeration threshold
MULTIPLE_ACCOUNTS_WINDOW = 300   # 5 minutes
AUTO_BLOCK_THRESHOLD = 10        # Auto-block after N attempts
```

### Redis Configuration

Ensure Redis is running and configured in `.env`:
```env
REDIS_HOST=localhost
REDIS_PORT=6379
```

## 📊 Monitoring & Analytics

### Key Metrics to Monitor

1. **Total Threats Detected** (last 24h)
2. **Auto-blocked IPs Count**
3. **Unresolved Threats**
4. **Threat Distribution by Level**
5. **Top Attacking IPs**
6. **Most Targeted Accounts**

### Dashboard Widgets (Suggested)

- Real-time threat feed (last 10 threats)
- Unread notifications badge
- Threat level pie chart
- Attack timeline graph
- Geo-location map of attacking IPs (future enhancement)

## 🔒 Security Considerations

### Best Practices

1. **Regular Review**: Check security threats dashboard daily
2. **Quick Response**: Resolve notifications promptly
3. **IP Whitelist**: Consider whitelisting legitimate IPs (VPN, office)
4. **False Positives**: Monitor for legitimate users getting blocked
5. **Log Retention**: Archive old threats after 90 days
6. **Rate Limiting**: Login endpoint already has rate limits (5/min)

### Proxy Headers

System checks for client IP in this order:
1. `X-Forwarded-For` header (first IP)
2. `X-Real-IP` header
3. Direct client IP from socket

Ensure your load balancer/proxy sets these headers correctly.

## 🚀 Future Enhancements

- [ ] Email alerts to admins for CRITICAL threats
- [ ] SMS alerts via Twilio integration
- [ ] Webhook support for external monitoring systems
- [ ] Machine learning-based anomaly detection
- [ ] Geo-blocking (block entire countries/regions)
- [ ] CAPTCHA challenge after N failures (before blocking)
- [ ] Temporary lockouts (15-min cooldown before permanent block)
- [ ] Export threat reports (CSV/PDF)
- [ ] Integration with threat intelligence feeds
- [ ] Behavioral analysis (unusual login times, locations)

## 🐛 Troubleshooting

### Issue: Threats not being detected
- Check Redis connection: `redis-cli ping`
- Verify service imports in auth.py
- Check logs for errors in ThreatDetectionService

### Issue: Legitimate users getting blocked
- Review thresholds (may be too strict)
- Check if behind proxy (IP detection)
- Manually unblock via blocked-ips endpoint

### Issue: Notifications not appearing
- Check threat_level (only HIGH/CRITICAL create notifications)
- Verify admin_notifications table exists
- Check notification query filters

## 📝 Database Migration

Tables will be auto-created by SQLAlchemy's `Base.metadata.create_all()` in development.

For production, create migration:
```bash
alembic revision -m "add_security_threat_tables"
alembic upgrade head
```

## 📚 Related Documentation

- [IP_BLOCKING_API.md](./IP_BLOCKING_API.md) - IP blocking system
- [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) - General API docs
- [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md) - Security features

---

**System Status**: ✅ Active
**Last Updated**: January 29, 2026
**Version**: 1.0.0

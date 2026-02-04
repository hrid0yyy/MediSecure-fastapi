# 🔥 Quick API Reference: Security Threat Detection

## Admin Endpoints (All require admin token)

### 🎯 Security Threats

```http
# List all threats
GET /api/v1/admin/security-threats?hours=24&is_resolved=false

# Get specific threat
GET /api/v1/admin/security-threats/{threat_id}

# Resolve a threat
PUT /api/v1/admin/security-threats/{threat_id}/resolve

# Get statistics
GET /api/v1/admin/security-threats/stats/summary?hours=24
```

### 🔔 Notifications

```http
# List notifications
GET /api/v1/admin/notifications?is_read=false

# Mark as read
PUT /api/v1/admin/notifications/{notification_id}/read

# Mark all as read
PUT /api/v1/admin/notifications/read-all

# Delete notification
DELETE /api/v1/admin/notifications/{notification_id}
```

### 🚫 IP Blocking (from previous feature)

```http
# Block an IP
POST /api/v1/admin/blocked-ips
Body: {"ip_address": "192.168.1.100", "reason": "Malicious activity"}

# List blocked IPs
GET /api/v1/admin/blocked-ips?is_active=true

# Unblock IP
DELETE /api/v1/admin/blocked-ips/{ip_id}
```

## Detection Thresholds

```
Failed Logins: 5 in 60 seconds → HIGH threat
Failed Logins: 10 in 60 seconds → AUTO-BLOCK

Account Enumeration: 3 accounts in 5 minutes → MEDIUM threat
Account Enumeration: 5 accounts in 5 minutes → AUTO-BLOCK
```

## Response Examples

### Threat List Response
```json
{
  "total": 15,
  "threats": [
    {
      "id": 1,
      "ip_address": "192.168.1.100",
      "threat_type": "brute_force",
      "threat_level": "critical",
      "attempt_count": 12,
      "is_blocked": true,
      "is_resolved": false
    }
  ]
}
```

### Statistics Response
```json
{
  "total_threats": 25,
  "auto_blocked_ips": 5,
  "unresolved_threats": 8,
  "by_level": {
    "high": 7,
    "critical": 3
  },
  "top_attacking_ips": [...]
}
```

### Notification Response
```json
{
  "total": 10,
  "unread_count": 3,
  "notifications": [
    {
      "id": 1,
      "title": "🚨 CRITICAL Security Threat Detected",
      "message": "IP 192.168.1.100 has been AUTO-BLOCKED",
      "severity": "critical",
      "is_read": false
    }
  ]
}
```

## cURL Examples

```bash
# Get unresolved threats
curl "http://localhost:8000/api/v1/admin/security-threats?is_resolved=false" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Resolve threat
curl -X PUT "http://localhost:8000/api/v1/admin/security-threats/1/resolve" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Check notifications
curl "http://localhost:8000/api/v1/admin/notifications?is_read=false" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get stats
curl "http://localhost:8000/api/v1/admin/security-threats/stats/summary" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Integration with Frontend

### Dashboard Widget: Threat Counter
```javascript
// Get unresolved threats count
fetch('/api/v1/admin/security-threats?is_resolved=false&limit=1')
  .then(res => res.json())
  .then(data => displayCount(data.total))
```

### Dashboard Widget: Unread Notifications
```javascript
// Get unread notification count
fetch('/api/v1/admin/notifications?is_read=false&limit=1')
  .then(res => res.json())
  .then(data => displayBadge(data.unread_count))
```

### Real-time Monitoring
```javascript
// Poll for new threats every 30 seconds
setInterval(async () => {
  const stats = await fetch('/api/v1/admin/security-threats/stats/summary?hours=1')
    .then(res => res.json())
  
  if (stats.unresolved_threats > 0) {
    showAlert(`${stats.unresolved_threats} unresolved threats`)
  }
}, 30000)
```

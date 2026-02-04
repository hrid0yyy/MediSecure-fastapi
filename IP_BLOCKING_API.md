# IP Blocking API Documentation

## Overview
The IP Blocking feature allows administrators to block specific IP addresses from accessing the API. This is useful for preventing malicious actors or abusive clients from making requests.

## Features
- Block/unblock IP addresses
- View all blocked IPs with filtering options
- Update blocked IP entries (reason, active status)
- Automatic IP blocking enforcement via middleware
- Audit trail (who blocked, when, why)

## How It Works
1. **Middleware Check**: Every incoming request passes through `IPBlockingMiddleware`
2. **IP Extraction**: Client IP is extracted from request (supports proxies via X-Forwarded-For)
3. **Database Lookup**: Checks if IP is in the blocked_ips table with is_active=True
4. **Block or Allow**: If blocked, returns 403 Forbidden; otherwise, request proceeds

## API Endpoints (Admin Only)

### 1. Block an IP Address
```http
POST /api/v1/admin/blocked-ips
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "ip_address": "192.168.1.100",
  "reason": "Suspected malicious activity"
}
```

**Response:**
```json
{
  "message": "IP address successfully blocked",
  "blocked_ip": {
    "id": 1,
    "ip_address": "192.168.1.100",
    "reason": "Suspected malicious activity",
    "blocked_by": "admin@example.com",
    "is_active": true,
    "created_at": "2026-01-29T10:00:00",
    "updated_at": "2026-01-29T10:00:00"
  }
}
```

### 2. List All Blocked IPs
```http
GET /api/v1/admin/blocked-ips?skip=0&limit=100&is_active=true
Authorization: Bearer <admin_token>
```

**Response:**
```json
{
  "total": 5,
  "skip": 0,
  "limit": 100,
  "blocked_ips": [
    {
      "id": 1,
      "ip_address": "192.168.1.100",
      "reason": "Suspected malicious activity",
      "blocked_by": "admin@example.com",
      "is_active": true,
      "created_at": "2026-01-29T10:00:00",
      "updated_at": "2026-01-29T10:00:00"
    }
  ]
}
```

### 3. Get Specific Blocked IP
```http
GET /api/v1/admin/blocked-ips/{ip_id}
Authorization: Bearer <admin_token>
```

### 4. Update Blocked IP
```http
PUT /api/v1/admin/blocked-ips/{ip_id}
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "reason": "Updated reason",
  "is_active": false
}
```

### 5. Unblock IP Address (Soft Delete)
```http
DELETE /api/v1/admin/blocked-ips/{ip_id}
Authorization: Bearer <admin_token>
```

Sets `is_active` to `false` but keeps the record for audit purposes.

### 6. Permanently Delete Blocked IP
```http
DELETE /api/v1/admin/blocked-ips/{ip_id}/permanent
Authorization: Bearer <admin_token>
```

⚠️ **Warning**: This permanently removes the record from the database.

## Database Migration

Run the migration to create the `blocked_ips` table:

```bash
# Using alembic (if installed)
alembic upgrade head

# Or let FastAPI auto-create tables (development only)
# Tables are auto-created when main.py runs: Base.metadata.create_all(bind=engine)
```

## Testing

### Test IP Blocking
1. Login as admin and get your auth token
2. Block your current IP address:
```bash
curl -X POST "http://localhost:8000/api/v1/admin/blocked-ips" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "127.0.0.1", "reason": "Test"}'
```

3. Try to access any API endpoint - you should get:
```json
{
  "detail": "Access forbidden. Your IP address has been blocked.",
  "ip": "127.0.0.1"
}
```

4. Unblock yourself:
```bash
curl -X DELETE "http://localhost:8000/api/v1/admin/blocked-ips/1" \
  -H "Authorization: Bearer <token>"
```

## Security Considerations

1. **Admin Only**: All IP blocking endpoints require admin authentication
2. **Proxy Support**: Middleware checks X-Forwarded-For and X-Real-IP headers
3. **Audit Trail**: Records who blocked each IP and when
4. **Soft Delete**: Default unblock operation keeps history
5. **IPv4/IPv6**: Supports both (max 45 characters for IPv6)

## Database Schema

```sql
CREATE TABLE blocked_ips (
    id INTEGER PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason TEXT,
    blocked_by VARCHAR NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME,
    updated_at DATETIME
);

CREATE INDEX ix_blocked_ips_ip_address ON blocked_ips(ip_address);
```

## Notes

- Middleware is placed early in the stack to block requests before they reach authentication
- IP blocking applies to ALL endpoints (including public ones)
- Consider implementing IP whitelisting for critical admin IPs
- Monitor blocked_ips table size and clean up old inactive records periodically

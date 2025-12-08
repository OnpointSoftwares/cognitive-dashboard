# Cognitive Security Dashboard

AI-powered security monitoring system with real-time threat detection and network analysis.

## Architecture

DFD-compliant microservices architecture:
- **API Gateway** (Port 8000) - Routes requests between services
- **Cognitive Dashboard** (Port 8001) - Main dashboard service
- **AI WAF** (Port 8002) - AI-powered Web Application Firewall
- **Network Monitor** (Port 8004) - Real-time network monitoring
- **Database** (Port 8005) - Centralized data storage

## Quick Start

### 1. Start Backend Services
```bash
cd backend
python3 run_dfd_system.py
```

### 2. Start Frontend
```bash
cd Frontend
npm start
```

### 3. Access Dashboard
- Open http://localhost:3000
- Login with: `admin / admin123` or `user / user123`

## Testing Scripts

### Basic System Health Check
```bash
# Check all services are running
curl -s http://localhost:8000/health
curl -s http://localhost:8001/health
curl -s http://localhost:8002/health
curl -s http://localhost:8004/health
curl -s http://localhost:8005/health
```

### Dashboard Data Testing
```bash
# Get dashboard overview
curl -s http://localhost:8001/dashboard

# Get request history
curl -s http://localhost:8001/history?limit=10

# Get system metrics
curl -s http://localhost:8001/metrics
```

### Network Monitoring Testing
```bash
# Get network statistics
curl -s http://localhost:8004/stats

# Get anomalous IPs (threshold 0.7)
curl -s http://localhost:8004/anomalies?threshold=0.7

# Get IP context for specific address
curl -s http://localhost:8004/context/192.168.1.100
```

### Security Testing - Malicious Requests

#### 1. SQL Injection Attack
```bash
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "sql_attacker",
    "request_data": {
      "source_ip": "192.168.1.200",
      "method": "POST",
      "uri": "/admin/login",
      "body": "username=admin&password=admin123 OR 1=1; DROP TABLE users; --",
      "user_agent": "sqlmap/1.0",
      "headers": {
        "X-Forwarded-For": "10.0.0.1"
      }
    }
  }'
```

#### 2. XSS Attack
```bash
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "xss_attacker",
    "request_data": {
      "source_ip": "172.16.0.50",
      "method": "POST",
      "uri": "/search",
      "body": "query=<script>alert(document.cookie)</script>",
      "user_agent": "Mozilla/5.0 (compatible; XSS-Bot/1.0)",
      "headers": {
        "Referer": "http://evil.com"
      }
    }
  }'
```

#### 3. DDoS Attack Simulation
```bash
# Single DDoS request
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "ddos_attacker",
    "request_data": {
      "source_ip": "10.0.0.100",
      "method": "GET",
      "uri": "/api/endpoint",
      "body": "",
      "user_agent": "DDoS-Bot/1.0"
    }
  }'

# Multiple rapid requests (DDoS simulation)
for i in {1..15}; do
  curl -X POST http://localhost:8001/process \
    -H "Content-Type: application/json" \
    -d "{
      \"user_id\": \"ddos_bot_$i\",
      \"request_data\": {
        \"source_ip\": \"10.0.0.200\",
        \"method\": \"GET\",
        \"uri\": \"/api/data\",
        \"body\": \"ddos_request_$i\",
        \"user_agent\": \"DDoS-Bot/1.0\"
      }
    }" &
  sleep 0.1
done
wait
```

#### 4. Brute Force Attack
```bash
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "brute_force_attacker",
    "request_data": {
      "source_ip": "192.168.1.150",
      "method": "POST",
      "uri": "/login",
      "body": "username=admin&password=pass123",
      "user_agent": "Hydra/9.0"
    }
  }'
```

#### 5. Command Injection Attack
```bash
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "cmd_injection_attacker",
    "request_data": {
      "source_ip": "10.0.1.50",
      "method": "POST",
      "uri": "/api/execute",
      "body": "command=ls; rm -rf /",
      "user_agent": "curl/7.68.0"
    }
  }'
```

### Legitimate Traffic Testing
```bash
# Normal user request
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "legitimate_user",
    "request_data": {
      "source_ip": "192.168.1.50",
      "method": "GET",
      "uri": "/dashboard",
      "body": "",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
  }'
```

### Automated Testing Script
```bash
#!/bin/bash
# comprehensive_test.sh

echo "=== Cognitive Security System Test ==="

# Test 1: Health checks
echo "1. Testing service health..."
services=("8000" "8001" "8002" "8004" "8005")
for port in "${services[@]}"; do
  health=$(curl -s http://localhost:$port/health | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
  echo "Port $port: $health"
done

# Test 2: Send various attack types
echo -e "\n2. Testing attack detection..."

# SQL Injection
echo "Sending SQL Injection..."
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{"user_id": "sql_test", "request_data": {"source_ip": "192.168.1.100", "method": "POST", "uri": "/login", "body": "admin OR 1=1", "user_agent": "sqlmap"}}' \
  -s | grep -o '"threat_level":"[^"]*"'

# XSS
echo "Sending XSS attack..."
curl -X POST http://localhost:8001/process \
  -H "Content-Type: application/json" \
  -d '{"user_id": "xss_test", "request_data": {"source_ip": "192.168.1.101", "method": "POST", "uri": "/search", "body": "<script>alert(1)</script>", "user_agent": "XSS-Bot"}}' \
  -s | grep -o '"threat_level":"[^"]*"'

# DDoS simulation
echo "Sending DDoS simulation..."
for i in {1..5}; do
  curl -X POST http://localhost:8001/process \
    -H "Content-Type: application/json" \
    -d "{\"user_id\": \"ddos_test_$i\", \"request_data\": {\"source_ip\": \"10.0.0.100\", \"method\": \"GET\", \"uri\": \"/api\", \"body\": \"\", \"user_agent\": \"DDoS-Bot\"}}" \
    -s > /dev/null &
done
wait

# Test 3: Check results
echo -e "\n3. Checking dashboard results..."
dashboard=$(curl -s http://localhost:8001/dashboard)
echo "Total requests: $(echo $dashboard | grep -o '"total_requests":[0-9]*' | cut -d':' -f2)"
echo "Blocked requests: $(echo $dashboard | grep -o '"blocked_requests":[0-9]*' | cut -d':' -f2)"
echo "Active threats: $(echo $dashboard | grep -o '"active_threats":[0-9]*' | cut -d':' -f2)"

echo -e "\n=== Test Complete ==="
```

## Monitoring Dashboard Features

### Overview Tab
- Real-time request metrics
- Blocked request statistics
- Active threat monitoring
- Recent activity feed

### Threat Detection Tab
- Critical/High/Medium risk classification
- Detailed threat analysis
- IP address tracking
- Action taken (BLOCK/MONITOR)

### Network Monitor Tab
- Connection statistics
- Bandwidth usage monitoring
- Anomalous IP detection
- Request/block ratios

### System Health Tab
- Service status monitoring
- Health check results
- System uptime tracking
- Error reporting

## API Endpoints

### Dashboard Service (Port 8001)
- `GET /health` - Service health check
- `GET /dashboard` - Comprehensive dashboard data
- `GET /metrics` - System metrics
- `GET /history?limit=N` - Request history
- `POST /process` - Process security request

### Network Monitor (Port 8004)
- `GET /health` - Service health check
- `GET /stats` - Network statistics
- `GET /anomalies?threshold=X` - Anomalous IPs
- `GET /context/{ip}` - IP context information
- `POST /track` - Track network event
- `POST /feedback` - Receive WAF feedback

### AI WAF Service (Port 8002)
- `GET /health` - Service health check
- `POST /analyze` - Analyze request for threats

### Database Service (Port 8005)
- `GET /health` - Service health check
- `GET /query/{collection}` - Query data
- `POST /store` - Store data

## Troubleshooting

### Common Issues
1. **CORS Errors**: Ensure backend services are running with CORS middleware
2. **Connection Refused**: Check if all services are started
3. **Empty Dashboard**: Send some test requests to generate data
4. **Port Conflicts**: Ensure ports 8000-8005 are available

### Reset System
```bash
# Stop all services (Ctrl+C in backend terminal)
# Clear browser cache
# Restart services
cd backend && python3 run_dfd_system.py
```

## Development

### Frontend Technologies
- React 18
- Modern CSS with inline styles
- Real-time data fetching
- Responsive design

### Backend Technologies
- FastAPI (Python)
- Machine Learning threat detection
- Microservices architecture
- Real-time data processing

### Security Features
- AI-powered threat detection
- Rate limiting
- IP reputation scoring
- Anomaly detection
- Real-time monitoring

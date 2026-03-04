# K6 Load Testing

Performance benchmarks for the Rinjani API.

## Install K6

```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

## Run Tests

```bash
# Basic test
k6 run apps/api/k6/loadtest.js

# With custom settings
k6 run --vus 20 --duration 60s apps/api/k6/loadtest.js

# Against staging
k6 run --env API_URL=https://api-staging.rinjani.io apps/api/k6/loadtest.js
```

## Metrics

| Threshold | Target |
|-----------|--------|
| p95 Response Time | < 500ms |
| Error Rate | < 10% |
| Health Check | < 100ms |
| IOC List | < 300ms |

## Output

Results are saved to `apps/api/k6/summary.json` after each run.

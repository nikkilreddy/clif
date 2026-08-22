#!/usr/bin/env bash
# =============================================================================
# Cognitive Log Investigation Platform — Local Hackathon Demo Launcher
# =============================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "================================================================="
echo "  🛡️  Launching Cognitive Log Investigation Platform Demo Mode..."
echo "================================================================="

# Check docker
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed or not in PATH."
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif [[ -x "/usr/local/cli-plugins/docker-compose" ]]; then
    COMPOSE=(/usr/local/cli-plugins/docker-compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "❌ Error: Docker Compose is not installed."
    exit 1
fi

echo "🚀 Starting single-replica local multi-agent stack (~5 GB RAM footprint)..."
"${COMPOSE[@]}" -f docker-compose.local.yml --profile demo up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 5

echo ""
echo "================================================================="
echo "  ✅ Cognitive Log Investigation Platform stack is running!"
echo "================================================================="
echo "  • SOC Dashboard    : http://localhost:3001"
echo "  • SecureBank Demo  : http://localhost:5001"
echo "  • ClickHouse HTTP  : http://localhost:8123"
echo "  • Redpanda Kafka   : localhost:9092"
echo "================================================================="
echo "  🧪 To run the 20-scenario Hackathon Eval Benchmark:"
echo "     python3 eval_harness.py"
echo "================================================================="

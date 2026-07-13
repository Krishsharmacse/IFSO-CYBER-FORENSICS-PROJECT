#!/usr/bin/env bash
# CyberX Forensics Platform — Linux/macOS Quick Start
# Starts backend and frontend side-by-side in the same terminal

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting CyberX Forensics Platform..."
echo

# Activate venv if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Start backend in background
echo "[1/2] Starting FastAPI backend on http://localhost:8000 ..."
cd backend
uv run --with uvicorn uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

sleep 1

# Start frontend in background
echo "[2/2] Starting React frontend on http://localhost:5173 ..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo
echo "Both services started."
echo "  Backend API : http://localhost:8000"
echo "  Frontend UI : http://localhost:5173"
echo "  API Docs    : http://localhost:8000/docs"
echo "  Diagnostics : http://localhost:8000/diagnostics"
echo
echo "Press Ctrl+C to stop both services."

# Wait for both processes, shut down cleanly on Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" INT TERM
wait $BACKEND_PID $FRONTEND_PID

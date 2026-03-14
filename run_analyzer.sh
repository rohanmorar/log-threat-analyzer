#!/bin/bash

# ─────────────────────────────────────────────
# run_analyzer.sh
# Called by cron every hour.
# Activates the venv and runs the log analyzer.
# All output appended to logs/cron.log
# ─────────────────────────────────────────────

# Absolute path to project — update this if your username differs
PROJECT_DIR="/home/kali/projects/log-parser"
VENV="$PROJECT_DIR/venv/bin/activate"
LOG="$PROJECT_DIR/logs/cron.log"
LOGFILE="/var/log/auth.log"

echo "──────────────────────────────────" >> "$LOG"
echo "Run started: $(date)" >> "$LOG"

# Activate virtual environment
source "$VENV"

# Run the analyzer, append all output to cron.log
python3 "$PROJECT_DIR/main.py" \
    --logfile "$LOGFILE" \
    --output "$PROJECT_DIR/output/report.json" \
    --threshold 5 >> "$LOG" 2>&1

echo "Run finished: $(date)" >> "$LOG"

#!/usr/bin/env bash
# Local server on a THROWAWAY sqlite file with the model switched off (mock), so tests cost nothing
# and never touch Supabase. Usage: ./run_local.sh   then in another terminal: python selftest.py
rm -f /tmp/mailroom_test.sqlite3*
MOCK_MODEL=1 DEBUG_STATS=1 DATABASE_URL= DATABASE_PATH=/tmp/mailroom_test.sqlite3 \
  uvicorn main:app --host 127.0.0.1 --port 8001 --workers 1
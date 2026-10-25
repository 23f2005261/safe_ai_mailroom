"""Empty all mailroom tables. Use after changing the prompt/validation so old cached decisions are not reused,
and once right before your real Checks:  python reset_db.py --yes"""
import os, sys
from dotenv import load_dotenv
load_dotenv()
if "--yes" not in sys.argv: raise SystemExit("This deletes ALL cached decisions and evaluations. Re-run with --yes")
import main
with main.Conn() as c:
    for t in ("evaluation_receipts", "evaluation_proposals", "evaluations", "dossier_cache"):
        c.x(f"DELETE FROM {t}")
print("cleared:", "postgres" if main.PG else main.DB)
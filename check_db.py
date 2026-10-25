"""Run this on your own machine BEFORE deploying:  python check_db.py
Confirms DATABASE_URL (Supabase) works: connect, create tables, write, read back, delete."""
import os
from dotenv import load_dotenv
load_dotenv()
url = os.getenv("DATABASE_URL", "").strip()
if not url.startswith(("postgres://", "postgresql://")):
    raise SystemExit("DATABASE_URL is missing or not a postgres URL. Fix .env first.")
if "[YOUR-PASSWORD]" in url:
    raise SystemExit("DATABASE_URL still contains the [YOUR-PASSWORD] placeholder.")
import psycopg2
conn = psycopg2.connect(url, connect_timeout=10)
cur = conn.cursor()
cur.execute("select current_database(), version()")
print("connected:", cur.fetchone())
import main  # creates the tables through the app's own initialize()
cur.execute("insert into dossier_cache values ('__probe__','__probe__','{}') on conflict do nothing")
cur.execute("select count(*) from dossier_cache where dossier_id='__probe__'"); print("probe rows:", cur.fetchone()[0])
cur.execute("delete from dossier_cache where dossier_id='__probe__'")
conn.commit(); conn.close()
print("OK: Supabase storage works")
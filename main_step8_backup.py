import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()
PROFILE = 'ga5-mailroom-action-gate/v2'
DB = os.getenv('DATABASE_PATH', 'mailroom.sqlite3')
ACTIONS = ['create_draft', 'update_internal_record', 'send_approved_notice', 'request_confirmation', 'quarantine_item', 'no_action']
MAX_BODY = 2_000_000
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def fail(code, status=400):
    return JSONResponse({'error': code}, status_code=status)


def db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=10000')
    return conn


def initialize():
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    with db() as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('''CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            request_hash TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            verifier_json TEXT NOT NULL,
            state TEXT NOT NULL,
            propose_json TEXT,
            commit_hash TEXT,
            commit_json TEXT
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS dossier_cache (
            dossier_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            proposal_json TEXT NOT NULL,
            PRIMARY KEY (dossier_id, fingerprint)
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS evaluation_proposals (
            evaluation_id TEXT NOT NULL,
            dossier_id TEXT NOT NULL,
            proposal_json TEXT NOT NULL,
            PRIMARY KEY (evaluation_id, dossier_id)
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS evaluation_receipts (
            evaluation_id TEXT NOT NULL,
            dossier_id TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            PRIMARY KEY (evaluation_id, dossier_id)
        )''')


initialize()


def valid_dossier(d):
    if not isinstance(d, dict):
        return False
    for field in ('dossierId', 'receivedAt', 'mailbox', 'objective'):
        if not isinstance(d.get(field), str) or not d[field]:
            return False
    if d.get('partition') not in ('stable_core', 'fresh_audit'):
        return False
    sources = d.get('sources')
    if not isinstance(sources, list):
        return False
    line_ids = set()
    for source in sources:
        if not isinstance(source, dict):
            return False
        for field in ('sourceId', 'kind', 'provenance', 'title'):
            if not isinstance(source.get(field), str):
                return False
        if not isinstance(source.get('lines'), list):
            return False
        for line in source['lines']:
            if not isinstance(line, dict) or not isinstance(line.get('lineId'), str) or not line['lineId'] or not isinstance(line.get('text'), str):
                return False
            if line['lineId'] in line_ids:
                return False
            line_ids.add(line['lineId'])
    return True


def validate_propose(body):
    eid = body.get('evaluationId')
    if not isinstance(eid, str) or not eid:
        return 'INVALID_EVALUATION_ID'
    verifier = body.get('receiptVerifier')
    if not isinstance(verifier, dict) or verifier.get('algorithm') != 'Ed25519':
        return 'INVALID_VERIFIER'
    jwk = verifier.get('publicKeyJwk')
    if not isinstance(jwk, dict) or jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519' or not isinstance(jwk.get('x'), str) or not jwk['x']:
        return 'INVALID_VERIFIER'
    import base64
    try:
        x = jwk['x']
        if len(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))) != 32:
            return 'INVALID_VERIFIER'
    except Exception:
        return 'INVALID_VERIFIER'
    corpus = body.get('corpus')
    if not isinstance(corpus, dict) or not all(isinstance(corpus.get(k), str) and corpus[k] for k in ('coreId', 'auditId')) or type(corpus.get('stableCount')) is not int or type(corpus.get('freshCount')) is not int:
        return 'INVALID_CORPUS'
    if body.get('allowedActions') != ACTIONS:
        # The contract defines the allowed set; the order is not significant.
        actions = body.get('allowedActions')
        if not isinstance(actions, list) or len(actions) != len(ACTIONS) or any(not isinstance(a, str) for a in actions) or set(actions) != set(ACTIONS):
            return 'INVALID_ACTIONS'
    dossiers = body.get('dossiers')
    if not isinstance(dossiers, list) or not dossiers:
        return 'INVALID_DOSSIERS'
    ids = set()
    stable = fresh = 0
    for dossier in dossiers:
        if not valid_dossier(dossier):
            return 'INVALID_DOSSIER'
        did = dossier['dossierId']
        if did in ids:
            return 'DUPLICATE_DOSSIER'
        ids.add(did)
        if dossier['partition'] == 'stable_core':
            stable += 1
        else:
            fresh += 1
    if stable != corpus['stableCount'] or fresh != corpus['freshCount']:
        return 'CORPUS_COUNT_MISMATCH'
    return None


@app.get('/')
def home():
    return {'status': 'online', 'service': 'Safe AI Mailroom', 'profile': PROFILE}


@app.post('/')
async def mailroom(request: Request):
    if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
        return fail('INVALID_CONTENT_TYPE', 415)
    if request.headers.get('content-length', '').isdigit() and int(request.headers['content-length']) > MAX_BODY:
        return fail('BODY_TOO_LARGE', 413)
    raw = await request.body()
    if len(raw) > MAX_BODY:
        return fail('BODY_TOO_LARGE', 413)
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return fail('INVALID_JSON')
    if not isinstance(body, dict):
        return fail('INVALID_REQUEST')
    if body.get('profile') != PROFILE:
        return fail('INVALID_PROFILE')
    if body.get('operation') not in ('propose', 'commit'):
        return fail('INVALID_OPERATION')
    if body['operation'] == 'commit':
        return fail('COMMIT_NOT_IMPLEMENTED', 501)
    issue = validate_propose(body)
    if issue:
        return fail(issue)
    eid = body['evaluationId']
    request_hash = digest(body)
    input_digest = digest(body['dossiers'])
    with db() as conn:
        prior = conn.execute('SELECT * FROM evaluations WHERE evaluation_id=?', (eid,)).fetchone()
        if prior:
            if prior['request_hash'] != request_hash:
                return fail('EVALUATION_CONFLICT', 409)
            if prior['propose_json']:
                return JSONResponse(json.loads(prior['propose_json']))
            return fail('EVALUATION_PENDING', 503)
        conn.execute('''INSERT INTO evaluations(evaluation_id,request_hash,input_digest,verifier_json,state)
                        VALUES(?,?,?,?,?)''', (eid, request_hash, input_digest, canonical(body['receiptVerifier']), 'pending'))
    # No fabricated proposals: the AI decision layer will fill this in next.
    return fail('PROPOSAL_ENGINE_NOT_IMPLEMENTED', 501)

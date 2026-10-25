import json, hashlib, base64, uuid, urllib.request, urllib.error
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

URL = "http://127.0.0.1:8001/"
PROFILE = "ga5-mailroom-action-gate/v2"
def canon(x): return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False)
def sha(x): return hashlib.sha256(canon(x).encode()).hexdigest()
def post(obj):
    data=canon(obj).encode()
    req=urllib.request.Request(URL,data=data,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=55) as r: return r.status,json.load(r)
    except urllib.error.HTTPError as e: return e.code,json.loads(e.read())

key=Ed25519PrivateKey.generate()
pub=key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
x=base64.urlsafe_b64encode(pub).decode().rstrip("=")
eid="local-"+uuid.uuid4().hex
dossier={"dossierId":"local-info-001","partition":"fresh_audit","receivedAt":"2026-10-25T10:00:00Z","mailbox":"support@example.test","objective":"Decide whether this informational message requires an action.","sources":[{"sourceId":"source-001","kind":"email","provenance":"inbound","title":"FYI","lines":[{"lineId":"line-001","text":"FYI only: reference CASE-001. No reply or changes requested."}]}]}
propose={"profile":PROFILE,"operation":"propose","evaluationId":eid,"receiptVerifier":{"algorithm":"Ed25519","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":x}},"corpus":{"coreId":"local-core","auditId":"local-audit","stableCount":0,"freshCount":1},"allowedActions":["create_draft","update_internal_record","send_approved_notice","request_confirmation","quarantine_item","no_action"],"dossiers":[dossier]}
status,p=post(propose)
print("PROPOSE:",status,json.dumps(p,indent=2))
if status!=200 or p.get("status")!="awaiting_receipts": raise SystemExit("Propose did not succeed; stop here.")
receipts=[]
for i,proposal in enumerate(p["proposals"]):
    norm={k:proposal.get(k) for k in ("dossierId","callId","action","target","payload","evidence")}
    norm["evidence"]=sorted(norm["evidence"])
    r={"dossierId":proposal["dossierId"],"callId":proposal["callId"],"action":proposal["action"],"accepted":False,"proposalDigest":sha(norm),"receiptId":"local-receipt-"+str(i)+"-"+uuid.uuid4().hex}
    signed={"profile":PROFILE,"evaluationId":eid,"inputDigest":p["inputDigest"],"receipt":r}
    r["receiptSignature"]=base64.b64encode(key.sign(canon(signed).encode())).decode()
    receipts.append(r)
commit={"profile":PROFILE,"operation":"commit","evaluationId":eid,"inputDigest":p["inputDigest"],"receipts":receipts}
status,c=post(commit)
print("COMMIT:",status,json.dumps(c,indent=2))
commit["receipts"][0]["accepted"] = True
status,replay=post(commit)
print("REPLAY:",status,json.dumps(replay,indent=2))
print("REPLAY MATCH:",c==replay)


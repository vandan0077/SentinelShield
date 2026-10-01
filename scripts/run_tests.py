"""Run benign/malicious test cases against a LOCAL SentinelShield instance."""
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import json

BASE = "http://127.0.0.1:5000/inspect"

CASES = [
    ("benign-search", "ALLOW", "q=hello-world"),
    ("benign-json", "ALLOW", "username=alice&note=meeting-at-10"),
    ("sqli-tautology", "BLOCK", "q=' OR '1'='1"),
    ("xss-script", "BLOCK", "q=<script>alert(1)</script>"),
    ("traversal", "BLOCK", "file=../../etc/passwd"),
    ("command-pattern", "BLOCK", "q=;whoami"),
]

def run():
    results=[]
    for name, expected, query in CASES:
        # CASES store raw query strings for readability; encode each value safely.
        pairs = []
        for part in query.split("&"):
            key, value = part.split("=", 1)
            pairs.append((key, value))
        url = f"{BASE}?{urlencode(pairs)}"
        req = Request(url, method="POST")
        try:
            with urlopen(req, timeout=5) as r:
                status = r.status
                body = json.loads(r.read().decode())
        except Exception as e:
            # HTTP 403/429 is an expected signal for blocked requests.
            status = getattr(e, 'code', None)
            if status not in (403, 429):
                raise
            body = json.loads(e.read().decode())
        detected = "BLOCK" if body.get("decision") == "BLOCK" else "ALLOW"
        # FLAG counts as non-allow for review, but none of the included cases should be FLAG.
        results.append({"name":name,"expected":expected,"actual":body.get("decision"),"status":status,"pass":detected==expected})
    tp=sum(r['expected']=='BLOCK' and r['actual']=='BLOCK' for r in results)
    tn=sum(r['expected']=='ALLOW' and r['actual']=='ALLOW' for r in results)
    fp=sum(r['expected']=='ALLOW' and r['actual']!='ALLOW' for r in results)
    fn=sum(r['expected']=='BLOCK' and r['actual']!='BLOCK' for r in results)
    accuracy=(tp+tn)/len(results)
    print(json.dumps({"results":results,"metrics":{"TP":tp,"TN":tn,"FP":fp,"FN":fn,"accuracy":accuracy}}, indent=2))

if __name__ == '__main__': run()

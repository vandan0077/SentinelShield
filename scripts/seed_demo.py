"""Generate a few harmless local requests for dashboard screenshots."""
from urllib.request import Request, urlopen
from urllib.parse import quote

BASE='http://127.0.0.1:5000/inspect'
values=['hello','project-demo','<script>alert(1)</script>','../../etc/passwd',"' OR '1'='1"]
for value in values:
    req=Request(BASE+'?q='+quote(value), method='POST')
    try:
        with urlopen(req, timeout=5) as r:
            print(value, r.status, r.read().decode())
    except Exception as e:
        code=getattr(e,'code',None)
        body=e.read().decode() if code in (403,429) else str(e)
        print(value, code, body)

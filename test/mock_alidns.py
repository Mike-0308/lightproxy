"""本地 mock 阿里云 DNS API，用于验证签名与增/改/查逻辑。"""
import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = "testsecret"
records = {}
seq = [0]


def pe(s):
    return urllib.parse.quote(str(s), safe="-_.~")


def verify(q):
    sig = q.get("Signature", [""])[0]
    params = {k: v[0] for k, v in q.items() if k != "Signature"}
    canon = "&".join(pe(k) + "=" + pe(params[k]) for k in sorted(params))
    sts = "GET&%2F&" + pe(canon)
    want = base64.b64encode(
        hmac.new((SECRET + "&").encode(), sts.encode(), hashlib.sha1).digest()
    ).decode()
    return sig == want


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path.startswith("/ip"):
            ip = open("test/ip.txt").read().strip()
            body = ip.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if not verify(q):
            print("REJECT bad signature", flush=True)
            return self.reply({"Code": "SignatureDoesNotMatch", "Message": "bad sig", "RequestId": "x"}, 400)

        action = q.get("Action", [""])[0]
        print("OK  ", action, {k: v[0] for k, v in q.items() if k in ("SubDomain", "Value", "RecordId", "RR", "Type")}, flush=True)

        if action == "DescribeDomains":
            zones = [z.strip() for z in os.environ.get("MOCK_ZONES", "381007.xyz,example.com").split(",") if z.strip()]
            return self.reply({"TotalCount": len(zones), "RequestId": "r1",
                               "Domains": {"Domain": [{"DomainName": z, "RecordCount": 0} for z in zones]}})

        if action == "DescribeSubDomainRecords":
            sub = q.get("SubDomain", [""])[0]
            out = []
            for (rr, dom, typ), rec in records.items():
                if sub in (dom, rr + "." + dom):
                    out.append({"RecordId": rec["id"], "RR": rr, "Type": typ,
                                "Value": rec["value"], "TTL": rec["ttl"], "Status": "ENABLE"})
            return self.reply({"TotalCount": len(out), "RequestId": "r2",
                               "DomainRecords": {"Record": out}})

        if action == "AddDomainRecord":
            seq[0] += 1
            rid = "rec%d" % seq[0]
            key = (q.get("RR", ["@"])[0], q.get("DomainName", [""])[0], q.get("Type", ["A"])[0])
            records[key] = {"id": rid, "value": q.get("Value", [""])[0], "ttl": int(q.get("TTL", ["600"])[0])}
            return self.reply({"RecordId": rid, "RequestId": "r3"})

        if action == "UpdateDomainRecord":
            rid = q.get("RecordId", [""])[0]
            for rec in records.values():
                if rec["id"] == rid:
                    rec["value"] = q.get("Value", [""])[0]
                    return self.reply({"RecordId": rid, "RequestId": "r4"})
            return self.reply({"Code": "DomainRecordNotBelongToUser", "Message": "not found", "RequestId": "x"}, 400)

        return self.reply({"Code": "InvalidAction", "Message": action, "RequestId": "x"}, 400)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()

#!/usr/bin/env python3
"""
🛠️ CodeArts 网页登录 / 凭据获取工具
------------------------------------------------------------
生成 PKCE + DPoP 登录链接 → 浏览器登录 → 本地回调自动换码 → 输出凭据 JSON

用法:
  python codearts_login.py                     # 自动开本地回调端口（推荐）
  python codearts_login.py --port 34567        # 指定回调端口
  python codearts_login.py --paste             # 不开端口，手动粘贴回调地址
  python codearts_login.py --note 主号         # 指定备注名
  python codearts_login.py --no-browser        # 不自动打开浏览器
  python codearts_login.py --no-verify         # 跳过登录后校验

输出（直接作为 CODEARTS_CREDENTIALS 的一行）:
  单行 JSON 凭据（含 AK/SK/STS、refresh_token、PKCE 与 DPoP 私钥，务必妥善保存）

依赖：requests + cryptography
说明：
  · 登录链接必须在与脚本同一台机器上的浏览器打开（回调指向 127.0.0.1）；
  · 青龙在服务器上时，先在本地电脑跑本工具，再把输出的 JSON 填进青龙变量；
  · 凭据自带到期时间，签到脚本会在到期前自动续期。
"""
import base64
import hashlib
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import urllib3
urllib3.disable_warnings()

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

WEB_LOGIN_BASE = "https://codearts.huaweicloud.com"
TOKEN_URL = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"
SNAP_ACCESS = "https://snap-access.cn-north-4.myhuaweicloud.com"
CLIENT_ID = "vscode-codebot"
PLUGIN_NAME = "snap_vscode"
PLUGIN_VERSION = "26.9.101"
CALLBACK_PATH = "/oauth/callback"
LOGIN_TIMEOUT = 300


def log(msg):
    print("%s %s" % (time.strftime("[%H:%M:%S]"), msg), flush=True)


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def encode_component(value):
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
    out = []
    for byte in value.encode("utf-8"):
        out.append(chr(byte) if byte in safe else "%%%02X" % byte)
    return "".join(out)


def sha256_b64(value):
    return b64url(hashlib.sha256(value.encode("utf-8")).digest())


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def url_port(callback_url):
    parsed = urllib.parse.urlsplit(callback_url)
    return str(parsed.port or "")


def build_authorize_url(ticket_id, code_challenge, callback_url, language="zh-CN",
                       plugin_name=PLUGIN_NAME, plugin_version=PLUGIN_VERSION,
                       web_login_base=WEB_LOGIN_BASE):
    locale = "zh-cn" if str(language or "").strip().lower().startswith("zh") else "en"
    pairs = [
        ("theme", "2"),
        ("locale", locale),
        ("uri_scheme", CLIENT_ID),
        ("client_id", CLIENT_ID),
        ("port", url_port(callback_url)),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "SHA-256"),
        ("ticket_id", ticket_id),
        ("auth_callback_url", callback_url),
        ("plugin-name", plugin_name),
        ("plugin-version", plugin_version),
    ]
    query = "&".join("%s=%s" % (key, encode_component(value)) for key, value in pairs)
    return web_login_base.rstrip("/") + "/portal/authorize?" + query


def new_dpop_key():
    """生成 P-256 私钥 JWK；返回 (private_jwk, signing_key)。"""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
    except Exception:
        raise RuntimeError("缺少 cryptography 库，无法生成 DPoP 密钥（pip install cryptography）")
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.private_numbers()
    public = numbers.public_numbers
    private_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(public.x.to_bytes(32, "big")),
        "y": b64url(public.y.to_bytes(32, "big")),
        "d": b64url(numbers.private_value.to_bytes(32, "big")),
    }
    return private_jwk, key


def public_jwk_of(private_jwk):
    return {"kty": "EC", "crv": "P-256", "x": private_jwk["x"], "y": private_jwk["y"]}


def dpop_proof(private_jwk, key, method, url):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": public_jwk_of(private_jwk)}
    payload = {"htm": method.upper(), "htu": url, "iat": int(time.time()), "jti": os.urandom(32).hex()}
    signing_input = "%s.%s" % (
        b64url(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
        b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
    )
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return "%s.%s" % (signing_input, b64url(raw))


def request(method, url, headers=None, data=None, timeout=30, retries=2):
    last = None
    for attempt in range(retries):
        try:
            session = requests.Session()
            session.trust_env = False
            return session.request(method, url, headers=headers or {}, data=data,
                                   timeout=timeout, verify=False)
        except Exception as error:
            last = error
            if attempt + 1 < retries:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError("请求失败: %s" % last)


def json_of(response):
    try:
        return response.json()
    except Exception:
        return {}


def first_text(*values):
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def exchange_code(code, code_verifier, callback_url, private_jwk, signing_key):
    log("🔐 用授权码换凭据 ...")
    proof = dpop_proof(private_jwk, signing_key, "POST", TOKEN_URL)
    form = {
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "redirect_uri": callback_url,
    }
    response = request("POST", TOKEN_URL,
                       headers={"Content-Type": "application/x-www-form-urlencoded",
                                "Accept": "application/json", "DPoP": proof},
                       data=form)
    payload = json_of(response)
    if response.status_code < 200 or response.status_code >= 300:
        detail = first_text(payload.get("error_description"), payload.get("error"),
                            payload.get("message")) or ("HTTP %s" % response.status_code)
        raise RuntimeError("令牌请求被拒：%s" % detail)
    return parse_credential(payload)


def fetch_ticket(ticket_id, secret):
    log("🎫 使用 ticket 通道换取凭据 ...")
    url = "%s/snap-manager/v1/login/ticket?%s" % (
        SNAP_ACCESS, urllib.parse.urlencode({"ticket_id": ticket_id, "secret": secret}))
    response = request("GET", url, headers={
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json",
        "plugin-name": PLUGIN_NAME,
        "plugin-version": PLUGIN_VERSION,
    })
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError("ticket 通道返回 HTTP %s" % response.status_code)
    payload = json_of(response)
    inner = payload.get("credential") if isinstance(payload.get("credential"), dict) else {}
    credential = {
        "access_key_id": first_text(inner.get("access")),
        "secret_access_key": first_text(inner.get("secret")),
        "security_token": first_text(inner.get("securitytoken")),
        "expiration": first_text(inner.get("expires_at")),
        "refresh_token": "",
        "domain_id": first_text(payload.get("domain_id")),
        "user_name": first_text(payload.get("user_name")),
    }
    if not credential["access_key_id"] or not credential["secret_access_key"] or not credential["security_token"]:
        raise RuntimeError("这条通道返回的凭据不完整")
    return credential


def parse_credential(payload):
    data = payload.get("credentials") if isinstance(payload.get("credentials"), dict) else payload
    read = lambda name: first_text(data.get(name), payload.get(name) if isinstance(payload.get(name), str) else "")
    credential = {
        "access_key_id": read("access_key_id"),
        "secret_access_key": read("secret_access_key"),
        "security_token": read("security_token"),
        "expiration": first_text(read("expiration"), read("expires_at")),
        "refresh_token": read("refresh_token"),
        "domain_id": read("domain_id"),
        "user_name": read("user_name"),
    }
    if not credential["access_key_id"] or not credential["secret_access_key"] or not credential["security_token"]:
        raise RuntimeError("响应里缺少 AK/SK/STS 三件套")
    if not credential["refresh_token"]:
        raise RuntimeError("令牌响应没有 refresh_token，该凭据无法续期（请重新登录）")
    return credential


def verify(credential):
    """用一次只读 ops 请求验证凭据可用（复用签到脚本里的签名实现）。"""
    log("🔎 校验凭据 ...")
    try:
        daily = os.path.join(os.path.dirname(os.path.abspath(__file__)), "codearts_daily.py")
        import importlib.util
        spec = importlib.util.spec_from_file_location("codearts_daily", daily)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        url = module.BASE + module.DELIVERY_PATH
        headers = {"Content-Type": "application/json", "Agent-Type": "PromptCenter", "X-Language": "en-us"}
        signed = module.sign_request("GET", url, headers, b"", credential, include_host=False)
        response = module.request("GET", url, headers=signed, timeout=20)
        payload = module.json_of(response)
        if response.status_code == 200 and payload.get("code") == 0:
            log("✅ 凭据可用（已读到福利活动列表）")
            return True
        log("⚠️ 校验返回 HTTP %s / code=%s" % (response.status_code, payload.get("code")))
    except Exception as error:
        log("⚠️ 校验异常：%s" % error)
    return False


class CallbackHandler(BaseHTTPRequestHandler):
    captured = {}
    event = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return
        CallbackHandler.captured = {key: values[0] for key, values in
                                    urllib.parse.parse_qs(parsed.query).items() if values}
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write("<h3>登录回调已收到，请回到终端查看结果。</h3>".encode("utf-8"))
        CallbackHandler.event.set()

    def log_message(self, *args):
        return


def wait_for_callback(port, timeout):
    server = ThreadingHTTPServer(("127.0.0.1", port), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if not CallbackHandler.event.wait(timeout):
            raise RuntimeError("等待回调超时，请重新运行")
        return dict(CallbackHandler.captured)
    finally:
        server.shutdown()
        server.server_close()


def parse_pasted_callback(raw, expected_ticket, callback_url):
    text = str(raw or "").strip()
    parsed = urllib.parse.urlsplit(text)
    query = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
    values = {key: items[0] for key, items in query.items() if items}
    # 只贴了 query 串（code=…&secret=…）也接受
    if not values and "=" in text:
        values = {key: items[0] for key, items in urllib.parse.parse_qs(text).items() if items}
    code = first_text(values.get("code"))
    secret = first_text(values.get("secret"))
    ticket = first_text(values.get("ticket_id"), values.get("ticketId"))
    if ticket and ticket != expected_ticket:
        raise ValueError("回调里的 ticket_id 与本次登录不一致，已拒绝")
    if not code and not secret:
        raise ValueError("回调地址里既没有 code 也没有 secret；请确认复制完整（%s）" % callback_url)
    return {"code": code, "secret": secret}


def main():
    args = sys.argv[1:]
    use_paste = "--paste" in args
    no_browser = "--no-browser" in args
    do_verify = "--no-verify" not in args
    note = ""
    if "--note" in args:
        try:
            note = args[args.index("--note") + 1]
        except Exception:
            note = ""
    port = 0
    if "--port" in args:
        try:
            port = int(args[args.index("--port") + 1])
        except Exception:
            port = 0
    if not port:
        port = free_port()
    callback_url = "http://127.0.0.1:%d%s" % (port, CALLBACK_PATH)

    print("╔══════════════════════════════════════════╗")
    print("║ 🛠️ CodeArts 网页登录                     ║")
    print("╚══════════════════════════════════════════╝")

    code_verifier = b64url(os.urandom(32))
    code_challenge = sha256_b64(code_verifier)
    ticket_id = os.urandom(16).hex()
    private_jwk, signing_key = new_dpop_key()
    authorize_url = build_authorize_url(ticket_id, code_challenge, callback_url)

    print("👉 请在**本机浏览器**打开下面的地址并完成登录：")
    print(authorize_url)
    if use_paste:
        print("📋 登录后浏览器会跳到 %s；把完整地址粘贴回终端。" % callback_url)
        if not no_browser:
            try:
                webbrowser.open(authorize_url)
            except Exception:
                pass
        raw = input("🔗 请粘贴回调地址（或 code=...&secret=...）: ").strip()
        values = parse_pasted_callback(raw, ticket_id, callback_url)
    else:
        print("⏳ 已监听 %s（最长 %d 秒）..." % (callback_url, LOGIN_TIMEOUT))
        if not no_browser:
            try:
                webbrowser.open(authorize_url)
            except Exception:
                pass
        values = wait_for_callback(port, LOGIN_TIMEOUT)

    if values.get("code"):
        credential = exchange_code(values["code"], code_verifier, callback_url, private_jwk, signing_key)
        credential["oauth_context"] = {
            "pkce_pair": {"code_verifier": code_verifier, "code_challenge": code_challenge,
                          "code_challenge_method": "SHA-256"},
            "dpop_key_pair": {"private_key_jwk": private_jwk, "public_key_jwk": public_jwk_of(private_jwk)},
        }
    else:
        credential = fetch_ticket(ticket_id, values["secret"])
        log("⚠️ 本次走 ticket 通道：没有 refresh_token，约 1 小时后到期，届时需重新登录")

    if note:
        credential["note"] = note
    if do_verify:
        verify(credential)

    env_line = json.dumps(credential, ensure_ascii=False, separators=(",", ":"))
    print("\n" + "-" * 50)
    print("✅ 将下面这行 JSON 追加到 CODEARTS_CREDENTIALS")
    print("-" * 50)
    print(env_line)
    print("-" * 50)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
    except Exception as error:
        print("❌ %s" % error)
        sys.exit(1)

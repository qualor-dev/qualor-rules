import http.client
import os
import socket
import ssl
import urllib.request
from ssl import CERT_NONE, _create_unverified_context, wrap_socket

import boto3
import certifi
import httpx
import jwt
import requests
import urllib3
from django.conf import settings
from flask import Flask, current_app
from httpx import AsyncClient
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib3.util import create_urllib3_context

app = Flask(__name__)

VERIFY_TLS = False
CA_BUNDLE = "/etc/ssl/certs/internal-ca.pem"


# requests: verify=False on the module functions accepts any certificate and any host name.
def requests_functions(url, payload):
    # ruleid: python.tls-verification-disabled
    requests.get(url, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.post(url, json=payload, timeout=5, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.put(url, data=payload, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.patch(url, data=payload, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.delete(url, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.head(url, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.options(url, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.request("GET", url, verify=False)
    # ruleid: python.tls-verification-disabled
    response = requests.get(
        url,
        params={"page": 1},
        verify=False,
    )
    # A module constant or a local variable that holds False.
    # ruleid: python.tls-verification-disabled
    requests.get(url, verify=VERIFY_TLS)
    check = False
    # ruleid: python.tls-verification-disabled
    requests.post(url, json=payload, verify=check)
    return response


# requests: a Session's request methods and its `verify` attribute.
def requests_sessions(url, payload, prepped):
    session = requests.Session()
    # ruleid: python.tls-verification-disabled
    session.get(url, verify=False)
    # ruleid: python.tls-verification-disabled
    session.request("POST", url, json=payload, verify=False)
    # ruleid: python.tls-verification-disabled
    session.send(prepped, verify=False)
    # ruleid: python.tls-verification-disabled
    session.verify = False
    with requests.Session() as s:
        # ruleid: python.tls-verification-disabled
        s.post(url, data=payload, verify=False)
        # ruleid: python.tls-verification-disabled
        s.verify = False
    imported = Session()
    # ruleid: python.tls-verification-disabled
    imported.verify = VERIFY_TLS
    # ruleid: python.tls-verification-disabled
    return requests.Session().get(url, verify=False)


# The lowercase factory kept for backwards compatibility, and the class by its module path.
def other_session_spellings(url, payload):
    legacy = requests.session()
    # ruleid: python.tls-verification-disabled
    legacy.verify = False
    # ruleid: python.tls-verification-disabled
    legacy.get(url, verify=False)
    with requests.session() as ls:
        # ruleid: python.tls-verification-disabled
        ls.post(url, json=payload, verify=False)
    # ruleid: python.tls-verification-disabled
    requests.session().get(url, verify=False)
    full = requests.sessions.Session()
    # ruleid: python.tls-verification-disabled
    full.get(url, verify=False)
    # ruleid: python.tls-verification-disabled
    return requests.sessions.Session().head(url, verify=False)


# A module-level Session is followed into the functions defined after its assignment, not into
# those defined above it.
def uses_shared_before(url):
    # todoruleid: python.tls-verification-disabled
    return SHARED_SESSION.get(url, verify=False)


SHARED_SESSION = requests.Session()


def uses_shared_after(url):
    # ruleid: python.tls-verification-disabled
    return SHARED_SESSION.get(url, verify=False)


def typed_session(session: requests.Session, url):
    # ruleid: python.tls-verification-disabled
    return session.get(url, verify=False)


def typed_imported_session(session: Session, url):
    # ruleid: python.tls-verification-disabled
    session.verify = False
    return session.get(url)


class ApiClient:
    def __init__(self, base):
        self.base = base
        self.http = requests.Session()
        # ruleid: python.tls-verification-disabled
        self.http.verify = False

    def fetch(self, path):
        # ruleid: python.tls-verification-disabled
        return self.http.get(self.base + path, verify=False)


class LegacyClient:
    def __init__(self):
        self.http = requests.session()

    def fetch(self, url):
        # ruleid: python.tls-verification-disabled
        return self.http.get(url, verify=False)


class LateSession:
    def setup(self):
        self.http = requests.Session()
        # ruleid: python.tls-verification-disabled
        self.http.verify = False

    def fetch(self, url):
        # A Session set on self outside __init__ is not followed into the other methods.
        # todoruleid: python.tls-verification-disabled
        return self.http.get(url, verify=False)


class AnnotatedClient:
    http: requests.Session

    def fetch(self, url):
        # A class attribute annotated as a Session is not followed.
        # todoruleid: python.tls-verification-disabled
        return self.http.get(url, verify=False)


class Worker:
    def __init__(self):
        session = requests.Session()
        self.session = session

    def call(self, api, url):
        # A local of another method that only shares the name of __init__'s local.
        session = api
        # ok: python.tls-verification-disabled
        return session.get(url, verify=False)


# httpx: verify=False on the module functions and on Client / AsyncClient.
async def httpx_clients(url, payload):
    # ruleid: python.tls-verification-disabled
    httpx.get(url, verify=False)
    # ruleid: python.tls-verification-disabled
    httpx.post(url, json=payload, verify=False)
    # ruleid: python.tls-verification-disabled
    httpx.request("DELETE", url, verify=False)
    # ruleid: python.tls-verification-disabled
    with httpx.stream("GET", url, verify=False) as streamed:
        streamed.read()
    # ruleid: python.tls-verification-disabled
    client = httpx.Client(verify=False)
    # ruleid: python.tls-verification-disabled
    with httpx.Client(base_url=url, verify=False) as c:
        c.get("/status")
    # ruleid: python.tls-verification-disabled
    async with httpx.AsyncClient(verify=False) as ac:
        await ac.get(url)
    # ruleid: python.tls-verification-disabled
    imported = AsyncClient(timeout=10, verify=VERIFY_TLS)
    return client, imported


# ssl: the unverified context (PEP 476), used directly, passed to urllib and http.client, or
# installed as the default for every HTTPS connection of the process.
def ssl_unverified(url, host):
    # ruleid: python.tls-verification-disabled
    ctx = ssl._create_unverified_context()
    # ruleid: python.tls-verification-disabled
    urllib.request.urlopen(url, context=ssl._create_unverified_context())
    # ruleid: python.tls-verification-disabled
    conn = http.client.HTTPSConnection(host, context=_create_unverified_context())
    # ruleid: python.tls-verification-disabled
    ssl._create_default_https_context = ssl._create_unverified_context
    # ruleid: python.tls-verification-disabled
    legacy = ssl._create_stdlib_context()
    return ctx, conn, legacy


# ssl: hostname checking off and verify_mode CERT_NONE on the same context.
def ssl_contexts(host):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # ruleid: python.tls-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    # ruleid: python.tls-verification-disabled
    client.verify_mode = CERT_NONE
    generic = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # ruleid: python.tls-verification-disabled
    generic.verify_mode = ssl.VerifyMode.CERT_NONE
    generic.check_hostname = False
    pooled = create_urllib3_context()
    pooled.check_hostname = False
    # ruleid: python.tls-verification-disabled
    pooled.verify_mode = ssl.CERT_NONE
    return ctx, client, generic, pooled


class Connector:
    def __init__(self):
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        # ruleid: python.tls-verification-disabled
        self.context.verify_mode = ssl.CERT_NONE


# urllib3: cert_reqs CERT_NONE (by name, by its abbreviation, or the ssl constant).
def urllib3_pools(url, host, proxy):
    # ruleid: python.tls-verification-disabled
    a = urllib3.PoolManager(cert_reqs="CERT_NONE")
    # ruleid: python.tls-verification-disabled
    b = urllib3.PoolManager(num_pools=4, cert_reqs=ssl.CERT_NONE)
    # ruleid: python.tls-verification-disabled
    c = urllib3.PoolManager(cert_reqs="NONE")
    # ruleid: python.tls-verification-disabled
    d = urllib3.ProxyManager(proxy, cert_reqs="CERT_NONE")
    # ruleid: python.tls-verification-disabled
    e = urllib3.HTTPSConnectionPool(host, port=443, cert_reqs="CERT_NONE")
    # ruleid: python.tls-verification-disabled
    f = urllib3.connection_from_url(url, cert_reqs=CERT_NONE)
    # ruleid: python.tls-verification-disabled
    g = create_urllib3_context(cert_reqs=ssl.CERT_NONE)
    return a, b, c, d, e, f, g


class InsecureAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        # ruleid: python.tls-verification-disabled
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            cert_reqs="CERT_NONE",
        )


# Safe: the defaults, verify=True, a CA bundle path, a verifying SSL context.
def safe_requests(url, payload):
    # ok: python.tls-verification-disabled
    requests.get(url)
    # ok: python.tls-verification-disabled
    requests.get(url, verify=True)
    # ok: python.tls-verification-disabled
    requests.post(url, json=payload, verify="/path/to/ca.pem")
    # ok: python.tls-verification-disabled
    requests.get(url, verify=certifi.where())
    # ok: python.tls-verification-disabled
    requests.get(url, verify=CA_BUNDLE)
    session = requests.Session()
    # ok: python.tls-verification-disabled
    session.verify = "/path/to/certfile"
    # ok: python.tls-verification-disabled
    session.verify = True
    # ok: python.tls-verification-disabled
    return session.get(url, timeout=5)


# Judgement: verify from configuration (settings, the environment, app config, a value that
# differs by branch) is not reported. The code lets the deployment keep verification on; a
# literal False, or a name that can only hold False, is reported.
def configured_verify(url, insecure):
    # ok: python.tls-verification-disabled
    requests.get(url, verify=settings.REQUESTS_VERIFY)
    # ok: python.tls-verification-disabled
    requests.get(url, verify=os.environ.get("REQUESTS_CA_BUNDLE", True))
    # ok: python.tls-verification-disabled
    httpx.get(url, verify=current_app.config["VERIFY_TLS"])
    if insecure:
        verify = False
    else:
        verify = CA_BUNDLE
    # The literal False inside a configuration branch is reported: the program itself carries
    # the off switch, whatever the deployment chooses.
    if insecure:
        # ruleid: python.tls-verification-disabled
        requests.get(url, verify=False)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        # ruleid: python.tls-verification-disabled
        ctx.verify_mode = ssl.CERT_NONE
    # ok: python.tls-verification-disabled
    return requests.get(url, verify=verify)


def safe_httpx(url):
    # ok: python.tls-verification-disabled
    httpx.get(url)
    # ok: python.tls-verification-disabled
    httpx.get(url, verify=True)
    ctx = ssl.create_default_context(cafile=certifi.where())
    # ok: python.tls-verification-disabled
    client = httpx.Client(verify=ctx)
    # ok: python.tls-verification-disabled
    other = httpx.AsyncClient(verify=ssl.create_default_context(cafile="path/to/certs.pem"))
    return client, other


def safe_ssl(url, host):
    ctx = ssl.create_default_context()
    # ok: python.tls-verification-disabled
    urllib.request.urlopen(url, context=ctx)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(CA_BUNDLE)
    # ok: python.tls-verification-disabled
    client.verify_mode = ssl.CERT_REQUIRED
    # ok: python.tls-verification-disabled
    client.check_hostname = True
    # A server context: CERT_NONE there means "ask the client for no certificate".
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.check_hostname = False
    # ok: python.tls-verification-disabled
    server.verify_mode = ssl.CERT_NONE
    listener = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
    listener.check_hostname = False
    # ok: python.tls-verification-disabled
    listener.verify_mode = ssl.VerifyMode.CERT_NONE
    accepting = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    accepting.check_hostname = False
    # ok: python.tls-verification-disabled
    accepting.verify_mode = ssl.CERT_NONE
    listening = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    listening.check_hostname = False
    # ok: python.tls-verification-disabled
    listening.verify_mode = CERT_NONE
    # ok: python.tls-verification-disabled
    return http.client.HTTPSConnection(host, context=ssl.create_default_context())


# ssl.wrap_socket() (deprecated since Python 3.7): cert_reqs defaults to CERT_NONE, so the client
# socket it makes accepts any certificate.
def legacy_wrap_socket(host, certfile, keyfile):
    sock = socket.create_connection((host, 443))
    # ruleid: python.tls-verification-disabled
    tls = ssl.wrap_socket(sock)
    # The CA bundle is loaded, but nothing asks for it to be used.
    # ruleid: python.tls-verification-disabled
    bundled = ssl.wrap_socket(sock, ca_certs=CA_BUNDLE)
    # ruleid: python.tls-verification-disabled
    explicit = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLS)
    # ruleid: python.tls-verification-disabled
    client_cert = ssl.wrap_socket(sock, keyfile, certfile, False, ssl.CERT_NONE)
    # ruleid: python.tls-verification-disabled
    client_side = ssl.wrap_socket(sock, server_side=False, certfile=certfile)
    # ruleid: python.tls-verification-disabled
    imported = wrap_socket(sock, cert_reqs=CERT_NONE)
    # ruleid: python.tls-verification-disabled
    enum_none = ssl.wrap_socket(sock, keyfile, certfile, cert_reqs=ssl.VerifyMode.CERT_NONE)
    return tls, bundled, explicit, client_cert, client_side, imported, enum_none


def safe_wrap_socket(host, certfile, keyfile, conn):
    sock = socket.create_connection((host, 443))
    # A server socket: CERT_NONE there means "ask the client for no certificate".
    # ok: python.tls-verification-disabled
    server = ssl.wrap_socket(conn, server_side=True, certfile=certfile, keyfile=keyfile)
    # ok: python.tls-verification-disabled
    positional_server = ssl.wrap_socket(conn, keyfile, certfile, True)
    # cert_reqs from the configuration: the deployment decides.
    # ok: python.tls-verification-disabled
    configured = ssl.wrap_socket(sock, cert_reqs=settings.TLS_CERT_REQS, ca_certs=CA_BUNDLE)
    # The documented replacement: a default context checks the chain and the host name.
    # ok: python.tls-verification-disabled
    modern = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    return server, positional_server, configured, modern


# A generic context the function then wraps on the server side of a connection.
def generic_server(certfile, keyfile, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.check_hostname = False
    # ok: python.tls-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    listener = socket.create_server(("", port))
    conn, _ = listener.accept()
    return ctx.wrap_socket(conn, server_side=True)


def generic_server_with(certfile, sock):
    ctx = ssl.SSLContext()
    ctx.load_cert_chain(certfile)
    # ok: python.tls-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    ctx.check_hostname = False
    with ctx.wrap_socket(sock, server_side=True) as tls:
        return tls.recv(1024)


def generic_server_bio(incoming, outgoing):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.check_hostname = False
    # ok: python.tls-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_bio(incoming, outgoing, server_side=True)
    return tls


# The same generic context wrapped on the client side stays reported.
def generic_client(host):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.check_hostname = False
    # ruleid: python.tls-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, 443))
    return ctx.wrap_socket(sock, server_hostname=host)


def safe_urllib3(url):
    # ok: python.tls-verification-disabled
    a = urllib3.PoolManager()
    # ok: python.tls-verification-disabled
    b = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())
    # ok: python.tls-verification-disabled
    c = urllib3.PoolManager(cert_reqs=ssl.CERT_REQUIRED)
    # ok: python.tls-verification-disabled
    d = create_urllib3_context()
    return a, b, c, d


# Look-alikes: a `verify` keyword or attribute, `check_hostname` and `verify_mode` on objects
# that are not HTTP clients or SSL contexts.
class Form:
    verify = True


def look_alikes(token, key, url, api, form: Form, settings_obj):
    # ok: python.tls-verification-disabled
    claims = jwt.decode(token, key, algorithms=["HS256"], verify=False)
    # ok: python.tls-verification-disabled
    api.get(url, verify=False)
    # ok: python.tls-verification-disabled
    form.verify = False
    settings_obj.check_hostname = False
    # ok: python.tls-verification-disabled
    settings_obj.verify_mode = "none"
    # ok: python.tls-verification-disabled
    report = {"verify": False, "url": url}
    # ok: python.tls-verification-disabled
    wrapped = api.wrap_socket(url)
    return claims, report, wrapped


# Known limits.
def known_limits(url, payload, make_session, host):
    # A session that comes from a factory function or another module has no type to bind to.
    session = make_session()
    # todoruleid: python.tls-verification-disabled
    session.get(url, verify=False)
    # Options passed as a dict (`**kwargs`) are not seen.
    # todoruleid: python.tls-verification-disabled
    requests.get(url, **{"verify": False})
    # httpx's transports take `verify` too, but the httpx documentation does not describe it.
    # todoruleid: python.tls-verification-disabled
    transport = httpx.HTTPTransport(verify=False)
    # Hostname checking turned off while the certificate chain is still verified is a narrower
    # weakness (CWE-297) than this rule's; it is not reported.
    ctx = ssl.create_default_context()
    # todoruleid: python.tls-verification-disabled
    ctx.check_hostname = False
    # todoruleid: python.tls-verification-disabled
    pool = urllib3.PoolManager(assert_hostname=False)
    # ssl.wrap_socket() checks the chain with CERT_REQUIRED, but never the host name.
    sock = socket.create_connection((host, 443))
    # todoruleid: python.tls-verification-disabled
    legacy = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs=CA_BUNDLE)
    # todoruleid: python.tls-verification-disabled
    optional = ssl.wrap_socket(sock, None, None, False, ssl.CERT_OPTIONAL, ca_certs=CA_BUNDLE)
    # ssl.wrap_socket()'s cert_reqs is read only as written in the call: a variable holding
    # CERT_NONE, and the number 0 (CERT_NONE's value), are not seen.
    reqs = ssl.CERT_NONE
    # todoruleid: python.tls-verification-disabled
    held = ssl.wrap_socket(sock, cert_reqs=reqs)
    # todoruleid: python.tls-verification-disabled
    zero = ssl.wrap_socket(sock, cert_reqs=0)
    # Options passed as a dict are not seen, so cert_reqs in them is taken for missing.
    # todook: python.tls-verification-disabled
    unpacked = ssl.wrap_socket(sock, **{"cert_reqs": ssl.CERT_REQUIRED, "ca_certs": CA_BUNDLE})
    # A context made by the SSLContext constructor without PROTOCOL_TLS_CLIENT verifies nothing
    # by default; whether it serves a client is not known where it is made.
    generic = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # todoruleid: python.tls-verification-disabled
    urllib.request.urlopen(url, context=generic)
    # The unverified context looked up by name (getattr), as PEP 476's opt-out does on old
    # Pythons, is not followed.
    # todoruleid: python.tls-verification-disabled
    ssl._create_default_https_context = getattr(ssl, "_create_unverified_context")
    # Other libraries' TLS switches are not in this rule (boto3, aiohttp, ...).
    # todoruleid: python.tls-verification-disabled
    s3 = boto3.client("s3", verify=False)
    return transport, pool, legacy, optional, held, zero, unpacked, s3


# A parameter whose default is False is configurable by the caller; it is not reported.
def fetch_with_default(url, verify=False):
    # todoruleid: python.tls-verification-disabled
    return requests.get(url, verify=verify)

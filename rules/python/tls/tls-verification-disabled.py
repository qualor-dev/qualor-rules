import hashlib
import http.client
import os
import socket
import ssl
import urllib.request
from ssl import CERT_NONE, _create_unverified_context, wrap_socket

import aiohttp
import asyncpg
import boto3
import botocore.session
import certifi
import httpx
import hvac
import jwt
import pymongo
import requests
import urllib3
from aiohttp import ClientSession, TCPConnector
from django.conf import settings
from elasticsearch import AsyncElasticsearch, Elasticsearch
from flask import Flask, current_app
from httpx import AsyncClient
from opensearchpy import OpenSearch
from pymongo import AsyncMongoClient, MongoClient
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib3.util import create_urllib3_context

app = Flask(__name__)

VERIFY_TLS = False
CHECK_HOSTNAME = False
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


# aiohttp: ssl=False skips certificate validation on a request, a session's request methods,
# ws_connect and a TCPConnector; verify_ssl=False is the deprecated spelling (TCPConnector since
# 2.3, the request methods since 3.0).
async def aiohttp_requests(url, payload):
    # ruleid: python.tls-verification-disabled
    async with aiohttp.request("GET", url, ssl=False) as resp:
        await resp.text()
    async with aiohttp.ClientSession() as session:
        # ruleid: python.tls-verification-disabled
        await session.get(url, ssl=False)
        # ruleid: python.tls-verification-disabled
        await session.post(url, json=payload, ssl=False)
        # ruleid: python.tls-verification-disabled
        await session.request("PUT", url, data=payload, ssl=False)
        # ruleid: python.tls-verification-disabled
        await session.get(url, verify_ssl=False)
        # ruleid: python.tls-verification-disabled
        ws = await session.ws_connect(url, ssl=False)
        # ruleid: python.tls-verification-disabled
        async with session.delete(url, ssl=VERIFY_TLS) as deleted:
            await deleted.release()
    plain = ClientSession()
    # ruleid: python.tls-verification-disabled
    await plain.head(url, ssl=False)
    await plain.close()
    return ws


async def aiohttp_connectors(url):
    # ruleid: python.tls-verification-disabled
    connector = aiohttp.TCPConnector(ssl=False)
    # ruleid: python.tls-verification-disabled
    legacy = TCPConnector(limit=10, verify_ssl=False)
    # ruleid: python.tls-verification-disabled
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        await session.get(url)
    # ruleid: python.tls-verification-disabled
    async with ClientSession(connector=TCPConnector(ssl=False), raise_for_status=True) as s:
        await s.get(url)
    return connector, legacy


async def typed_aiohttp_session(session: aiohttp.ClientSession, url):
    # ruleid: python.tls-verification-disabled
    return await session.get(url, ssl=False)


class AioClient:
    def __init__(self):
        self.http = aiohttp.ClientSession()

    async def fetch(self, url):
        # ruleid: python.tls-verification-disabled
        return await self.http.get(url, ssl=False)


def make_aiohttp_session():
    return aiohttp.ClientSession()


async def safe_aiohttp(url, digest):
    ctx = ssl.create_default_context(cafile=CA_BUNDLE)
    async with aiohttp.ClientSession() as session:
        # ok: python.tls-verification-disabled
        await session.get(url)
        # ok: python.tls-verification-disabled
        await session.get(url, ssl=True)
        # ok: python.tls-verification-disabled
        await session.post(url, ssl=ctx)
        # The certificate pinned by its SHA-256 fingerprint.
        # ok: python.tls-verification-disabled
        await session.get(url, ssl=aiohttp.Fingerprint(digest))
        # The setting from configuration: the deployment decides.
        # ok: python.tls-verification-disabled
        await session.get(url, ssl=settings.AIOHTTP_SSL)
        # ok: python.tls-verification-disabled
        await session.get(url, verify_ssl=True)
    # ok: python.tls-verification-disabled
    connector = aiohttp.TCPConnector(ssl=ctx)
    # ok: python.tls-verification-disabled
    pooled = TCPConnector(limit=10)
    # ok: python.tls-verification-disabled
    async with aiohttp.request("GET", url, ssl=ctx) as resp:
        await resp.text()
    return connector, pooled


# Look-alikes: `ssl=False` on clients that are not aiohttp's (for a database driver it means "no
# TLS", not "TLS without verification"), and on an object of unknown type.
async def ssl_keyword_look_alikes(dsn, api, url):
    # ok: python.tls-verification-disabled
    conn = await asyncpg.connect(dsn, ssl=False)
    # ok: python.tls-verification-disabled
    resp = await api.get(url, ssl=False)
    return conn, resp


async def aiohttp_limits(url):
    # A session that comes from a factory function has no type to bind to.
    session = make_aiohttp_session()
    # todoruleid: python.tls-verification-disabled
    await session.get(url, ssl=False)
    # Options passed as a dict are not seen.
    async with aiohttp.ClientSession() as known:
        # todoruleid: python.tls-verification-disabled
        await known.get(url, **{"ssl": False})

# SDKs whose documentation names a switch that turns certificate validation off: boto3 and
# botocore clients (verify=False), Elasticsearch and OpenSearch (verify_certs=False), PyMongo
# (tlsInsecure, tlsAllowInvalidCertificates, tlsAllowInvalidHostnames, also in the connection
# string) and hvac (verify=False).
def sdk_clients(url, endpoint, token, region):
    # ruleid: python.tls-verification-disabled
    s3 = boto3.client("s3", verify=False)
    # ruleid: python.tls-verification-disabled
    dynamo = boto3.resource("dynamodb", region_name=region, verify=False)
    aws = boto3.Session(profile_name="ops")
    # ruleid: python.tls-verification-disabled
    sqs = aws.client("sqs", endpoint_url=endpoint, verify=False)
    full = boto3.session.Session()
    # ruleid: python.tls-verification-disabled
    sns = full.resource("sns", verify=VERIFY_TLS)
    # ruleid: python.tls-verification-disabled
    ec2 = boto3.Session().client("ec2", verify=False)
    # ruleid: python.tls-verification-disabled
    kms = botocore.session.get_session().create_client("kms", verify=False)
    core = botocore.session.get_session()
    # ruleid: python.tls-verification-disabled
    sts = core.create_client("sts", region_name=region, verify=False)
    # ruleid: python.tls-verification-disabled
    es = Elasticsearch(url, verify_certs=False)
    # ruleid: python.tls-verification-disabled
    es_async = AsyncElasticsearch(url, api_key=token, verify_certs=False)
    # ruleid: python.tls-verification-disabled
    search = OpenSearch(hosts=[{"host": endpoint, "port": 9200}], use_ssl=True, verify_certs=False)
    # ruleid: python.tls-verification-disabled
    mongo = pymongo.MongoClient(url, tls=True, tlsInsecure=True)
    # ruleid: python.tls-verification-disabled
    mongo_certs = MongoClient(url, tls=True, tlsAllowInvalidCertificates=True)
    # ruleid: python.tls-verification-disabled
    mongo_hosts = MongoClient(url, tls=True, tlsAllowInvalidHostnames=True)
    # ruleid: python.tls-verification-disabled
    mongo_uri = MongoClient("mongodb://db.example.com:27017/?tls=true&tlsInsecure=true")
    # ruleid: python.tls-verification-disabled
    mongo_srv = pymongo.MongoClient("mongodb+srv://cluster.example.com/?tlsAllowInvalidCertificates=true")
    # PyMongo's asyncio client takes the same options.
    # ruleid: python.tls-verification-disabled
    amongo = pymongo.AsyncMongoClient(url, tls=True, tlsInsecure=True)
    # ruleid: python.tls-verification-disabled
    amongo_certs = AsyncMongoClient(url, tls=True, tlsAllowInvalidCertificates=True)
    # ruleid: python.tls-verification-disabled
    amongo_hosts = AsyncMongoClient(url, tls=True, tlsAllowInvalidHostnames=True)
    # ruleid: python.tls-verification-disabled
    amongo_uri = AsyncMongoClient("mongodb://db.example.com:27017/?tls=true&tlsAllowInvalidHostnames=true")
    # ruleid: python.tls-verification-disabled
    vault = hvac.Client(url=url, token=token, verify=False)
    # A list of https hosts, or of hosts given as dicts, is TLS.
    # ruleid: python.tls-verification-disabled
    es_list = Elasticsearch(["https://es1.example.com:9200"], verify_certs=False)
    # ruleid: python.tls-verification-disabled
    es_hosts = Elasticsearch(hosts=["https://es1.example.com:9200", "https://es2.example.com:9200"], verify_certs=False)
    return (s3, dynamo, sqs, sns, ec2, kms, sts, es, es_async, search, mongo, mongo_certs,
            mongo_hosts, mongo_uri, mongo_srv, amongo, amongo_certs, amongo_hosts, amongo_uri,
            vault, es_list, es_hosts)


class SearchWrapper:
    def __init__(self, url, verify_certs=True):
        self.url = url
        self.verify_certs = verify_certs


def safe_sdk_clients(url, endpoint, token, fingerprint, make_client):
    # ok: python.tls-verification-disabled
    s3 = boto3.client("s3")
    # ok: python.tls-verification-disabled
    s3_ca = boto3.client("s3", verify=CA_BUNDLE)
    # Plain HTTP (use_ssl=False, or an http:// endpoint such as a local emulator): there is no
    # certificate to verify.
    # ok: python.tls-verification-disabled
    local = boto3.client("s3", endpoint_url=endpoint, use_ssl=False, verify=False)
    # ok: python.tls-verification-disabled
    emulator = boto3.client("s3", endpoint_url="http://localhost:4566", verify=False)
    # ok: python.tls-verification-disabled
    local_es = Elasticsearch("http://localhost:9200", verify_certs=False)
    # ok: python.tls-verification-disabled
    local_hosts = Elasticsearch(hosts="http://localhost:9200", verify_certs=False)
    # ok: python.tls-verification-disabled
    local_list = Elasticsearch(["http://localhost:9200"], verify_certs=False)
    # ok: python.tls-verification-disabled
    local_hosts_list = Elasticsearch(hosts=["http://es1:9200", "http://es2:9200"], verify_certs=False)
    # ok: python.tls-verification-disabled
    search = OpenSearch(hosts=[{"host": endpoint, "port": 9200}], use_ssl=False, verify_certs=False)
    # ok: python.tls-verification-disabled
    es = Elasticsearch(url, ca_certs=CA_BUNDLE)
    # ok: python.tls-verification-disabled
    es_verified = Elasticsearch(url, verify_certs=True)
    # The certificate pinned by its fingerprint.
    # ok: python.tls-verification-disabled
    es_pinned = Elasticsearch(url, verify_certs=False, ssl_assert_fingerprint=fingerprint)
    # ok: python.tls-verification-disabled
    mongo = MongoClient(url, tls=True, tlsCAFile=CA_BUNDLE)
    # ok: python.tls-verification-disabled
    mongo_uri = MongoClient("mongodb://db.example.com:27017/?tls=true&tlsCAFile=/etc/ca.pem")
    # ok: python.tls-verification-disabled
    mongo_off = MongoClient(url, tlsInsecure=False)
    # ok: python.tls-verification-disabled
    amongo = AsyncMongoClient(url, tls=True, tlsCAFile=CA_BUNDLE)
    # ok: python.tls-verification-disabled
    amongo_uri = AsyncMongoClient("mongodb://db.example.com:27017/?tls=true&tlsInsecure=false")
    # ok: python.tls-verification-disabled
    vault = hvac.Client(url=url, token=token, verify=CA_BUNDLE)
    # The setting from configuration: the deployment decides.
    # ok: python.tls-verification-disabled
    configured = boto3.client("s3", verify=settings.AWS_VERIFY)
    # Look-alikes: a verify or verify_certs keyword on functions of other libraries.
    # ok: python.tls-verification-disabled
    other = make_client("s3", verify=False)
    # ok: python.tls-verification-disabled
    other_es = SearchWrapper(url, verify_certs=False)
    return (s3, s3_ca, local, emulator, local_es, local_hosts, local_list, local_hosts_list, search,
            es, es_verified, es_pinned, mongo, mongo_uri, mongo_off, amongo, amongo_uri, vault,
            configured, other, other_es)


def sdk_limits(url, region):
    # The switch passed by position (verify is client()'s fifth parameter) or in a dict is not
    # seen.
    # todoruleid: python.tls-verification-disabled
    s3 = boto3.client("s3", region, None, True, False)
    # todoruleid: python.tls-verification-disabled
    es = Elasticsearch(url, **{"verify_certs": False})
    # A connection string built at run time is not read.
    # todoruleid: python.tls-verification-disabled
    mongo = MongoClient(url + "/?tls=true&tlsInsecure=true")
    # Only a list whose first host is written as http:// is taken for plain HTTP: a list that
    # mixes http:// and https:// hosts is not reported.
    # todoruleid: python.tls-verification-disabled
    mixed = Elasticsearch(["http://es1:9200", "https://es2.example.com:9200"], verify_certs=False)
    return s3, es, mongo, mixed

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


# Host name checking off while the chain is still verified (CWE-297): the client takes any
# certificate its trust store accepts, issued for any host, so whoever holds one can pose as the
# server. Reported on the line that turns the check off.
def hostname_unchecked(host):
    ctx = ssl.create_default_context()
    # ruleid: python.tls-verification-disabled
    ctx.check_hostname = False
    private_ca = ssl.create_default_context(cafile=CA_BUNDLE)
    # ruleid: python.tls-verification-disabled
    private_ca.check_hostname = False
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(CA_BUNDLE)
    # ruleid: python.tls-verification-disabled
    client.check_hostname = False
    keyword = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
    # ruleid: python.tls-verification-disabled
    keyword.check_hostname = CHECK_HOSTNAME
    # The chain is still required: the host name is not.
    required = ssl.create_default_context()
    # ruleid: python.tls-verification-disabled
    required.check_hostname = False
    # ok: python.tls-verification-disabled
    required.verify_mode = ssl.CERT_REQUIRED
    sock = socket.create_connection((host, 443))
    return ctx.wrap_socket(sock), private_ca, client, keyword, required


class HostConnector:
    def __init__(self):
        self.context = ssl.create_default_context()
        # ruleid: python.tls-verification-disabled
        self.context.check_hostname = False


# urllib3: assert_hostname=False ("no verification is done" of the host name).
def urllib3_hostname(url, host, proxy):
    # ruleid: python.tls-verification-disabled
    a = urllib3.PoolManager(assert_hostname=False)
    # ruleid: python.tls-verification-disabled
    b = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=CA_BUNDLE, assert_hostname=False)
    # ruleid: python.tls-verification-disabled
    c = urllib3.HTTPSConnectionPool(host, port=443, assert_hostname=False)
    # ruleid: python.tls-verification-disabled
    d = urllib3.ProxyManager(proxy, assert_hostname=False)
    # ruleid: python.tls-verification-disabled
    e = urllib3.connection_from_url(url, assert_hostname=False)
    # ruleid: python.tls-verification-disabled
    f = PoolManager(num_pools=2, assert_hostname=False)
    return a, b, c, d, e, f


# ssl.wrap_socket() checks the chain with CERT_REQUIRED or CERT_OPTIONAL, but never the host name.
def legacy_wrap_socket_hostname(host):
    sock = socket.create_connection((host, 443))
    # ruleid: python.tls-verification-disabled
    legacy = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs=CA_BUNDLE)
    # ruleid: python.tls-verification-disabled
    optional = ssl.wrap_socket(sock, None, None, False, ssl.CERT_OPTIONAL, ca_certs=CA_BUNDLE)
    # ruleid: python.tls-verification-disabled
    enum_required = ssl.wrap_socket(sock, cert_reqs=ssl.VerifyMode.CERT_REQUIRED, ca_certs=CA_BUNDLE)
    # ruleid: python.tls-verification-disabled
    imported = wrap_socket(sock, ca_certs=CA_BUNDLE, cert_reqs=ssl.CERT_OPTIONAL)
    return legacy, optional, enum_required, imported


def hostname_checked(host, fingerprint):
    ctx = ssl.create_default_context()
    # ok: python.tls-verification-disabled
    ctx.check_hostname = True
    # Server contexts: there is no host name to check.
    accepting = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # ok: python.tls-verification-disabled
    accepting.check_hostname = False
    listening = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    # ok: python.tls-verification-disabled
    listening.check_hostname = False
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # ok: python.tls-verification-disabled
    server.check_hostname = False
    # The check from configuration: the deployment decides.
    configured = ssl.create_default_context()
    # ok: python.tls-verification-disabled
    configured.check_hostname = settings.TLS_CHECK_HOSTNAME
    # urllib3: the expected host name given, or the certificate pinned by its fingerprint (which
    # urllib3 checks before assert_hostname).
    # ok: python.tls-verification-disabled
    a = urllib3.PoolManager(assert_hostname="internal.example.com")
    # ok: python.tls-verification-disabled
    b = urllib3.HTTPSConnectionPool(host, assert_hostname=False, assert_fingerprint=fingerprint)
    # ok: python.tls-verification-disabled
    c = urllib3.PoolManager(server_hostname="internal.example.com")
    # ok: python.tls-verification-disabled
    d = urllib3.PoolManager(assert_hostname=None)
    return ctx, accepting, listening, server, configured, a, b, c, d


# The code matches the host name itself: ssl.match_hostname() (Python 3.11 and older) on the
# certificate of the connection.
def hostname_matched_by_code(host):
    sock = socket.create_connection((host, 443))
    # ok: python.tls-verification-disabled
    tls = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs=CA_BUNDLE)
    ssl.match_hostname(tls.getpeercert(), host)
    ctx = ssl.create_default_context()
    # ok: python.tls-verification-disabled
    ctx.check_hostname = False
    with ctx.wrap_socket(sock) as conn:
        ssl.match_hostname(conn.getpeercert(), host)
        return conn.recv(1024)


# The code compares the server's certificate (DER bytes) with a pinned one.
def certificate_pinned(host, expected_sha256):
    ctx = ssl.create_default_context(cafile=CA_BUNDLE)
    # ok: python.tls-verification-disabled
    ctx.check_hostname = False
    sock = socket.create_connection((host, 443))
    with ctx.wrap_socket(sock) as conn:
        der = conn.getpeercert(binary_form=True)
        if hashlib.sha256(der).hexdigest() != expected_sha256:
            raise ssl.SSLError("certificate does not match the pinned one")
        return conn.recv(1024)


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
def known_limits(url, payload, make_session, host, self_made):
    # A session that comes from a factory function or another module has no type to bind to.
    session = make_session()
    # todoruleid: python.tls-verification-disabled
    session.get(url, verify=False)
    # Options passed as a dict (`**kwargs`) are not seen.
    # todoruleid: python.tls-verification-disabled
    requests.get(url, **{"verify": False})
    # httpx's transports take `verify` too, but neither the httpx documentation nor the
    # transports' docstrings describe it (only their signatures name it).
    # todoruleid: python.tls-verification-disabled
    transport = httpx.HTTPTransport(verify=False)
    # todoruleid: python.tls-verification-disabled
    async_transport = httpx.AsyncHTTPTransport(retries=1, verify=False)
    # Host name checking off on a context made by SSLContext() without PROTOCOL_TLS_CLIENT, or
    # by urllib3's create_urllib3_context(), is not reported: whether it serves a client that
    # relies on it is not known where it is made.
    generic_required = ssl.SSLContext(ssl.PROTOCOL_TLS)
    generic_required.verify_mode = ssl.CERT_REQUIRED
    # todoruleid: python.tls-verification-disabled
    generic_required.check_hostname = False
    pooled = create_urllib3_context()
    # todoruleid: python.tls-verification-disabled
    pooled.check_hostname = False
    # A context made in another method (or another function) is not followed.
    # todoruleid: python.tls-verification-disabled
    self_made.context.check_hostname = False
    # A function that reads the server's certificate as DER bytes counts as pinning it, whatever
    # it does with the bytes.
    pinned_ctx = ssl.create_default_context()
    # todoruleid: python.tls-verification-disabled
    pinned_ctx.check_hostname = False
    logged = pinned_ctx.wrap_socket(socket.create_connection((host, 443)))
    print(logged.getpeercert(binary_form=True))
    # The check turned off only when the caller gives no host name to check (a library helper
    # whose callers decide) is still reported.
    nameless = ssl.create_default_context()
    if not host:
        # todook: python.tls-verification-disabled
        nameless.check_hostname = False
    sock = socket.create_connection((host, 443))
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
    return transport, async_transport, generic_required, pooled, held, zero, unpacked


# A parameter whose default is False is configurable by the caller; it is not reported.
def fetch_with_default(url, verify=False):
    # todoruleid: python.tls-verification-disabled
    return requests.get(url, verify=verify)

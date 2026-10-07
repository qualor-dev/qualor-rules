import json
import os
from typing import Annotated
import urllib.request
from urllib.parse import quote, urljoin, urlparse

import aiohttp
import httpx
import requests
from config import CONFIG_API_URL
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views import View
from fastapi import Depends, FastAPI, Path, Query, Request
from flask import Flask, request
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()

API = "https://api.example.com"
ALLOWED_HOSTS = {"images.example.com", "cdn.example.com"}
MIRRORS = {"eu": "https://eu.example.com/feed", "us": "https://us.example.com/feed"}
STATUS_PAGES = {
    # Health checks the admin page may run; the request only picks one.
    "api": r"https://api.example.com/health",
    "cdn": u"https://cdn.example.com/health",  # a u prefix
}
API_BASE = "https://api.example.com"
API_ROOT = "https://api.example.com/"
API_V2 = "https://api.example.com/v2/"
API_HOST = "api.example.com"
SCHEME = "https:"
ROOT_PATH = "/"
ENV_API_URL = os.environ.get("API_URL", "https://api.example.com")
# Changed later by a view, so not an allow-list.
PARTNERS = {"acme": "https://acme.example.com/hook"}


# Flask: query strings, form fields, headers, cookies, JSON bodies and URL variables.
@app.route("/fetch")
def fetch():
    url = request.args["url"]
    # ruleid: python.ssrf
    resp = requests.get(url)
    # ruleid: python.ssrf
    requests.post(request.form["callback"], json={"done": True})
    # ruleid: python.ssrf
    requests.request("GET", request.headers["X-Upstream"])
    # ruleid: python.ssrf
    requests.get(url=request.cookies["avatar"], timeout=5)
    # ruleid: python.ssrf
    requests.get(f"https://{request.args['host']}/status")
    # ruleid: python.ssrf
    requests.get("https://" + request.args["host"] + "/status")
    # ruleid: python.ssrf
    requests.get("https://%s/status" % request.args["host"])
    # ruleid: python.ssrf
    requests.get(API + request.args["path"])
    # ok: python.ssrf
    requests.get(f"https://api.example.com/users/{request.args['id']}")
    # ok: python.ssrf
    requests.get("https://api.example.com/users/" + request.args["id"])
    # ok: python.ssrf
    requests.get("https://api.example.com/users/{}".format(request.args["id"]))
    # ok: python.ssrf
    requests.get("https://api.example.com/search", params={"q": request.args["q"]})
    # ok: python.ssrf
    requests.post("https://hooks.example.com/notify", json=request.get_json())
    feed = MIRRORS["eu"] if request.args.get("region") == "eu" else MIRRORS["us"]
    # ok: python.ssrf
    requests.get(feed)
    # ok: python.ssrf
    requests.get("https://api.example.com/health")
    return resp.text


@app.post("/proxy/<path:target>")
def proxy(target):
    body = request.get_json()
    with requests.Session() as session:
        # ruleid: python.ssrf
        session.get(target)
        # ruleid: python.ssrf
        session.request("POST", body["webhook"], data=b"ping")
        # ok: python.ssrf
        session.get("https://api.example.com/items/" + target)
    s = requests.Session()
    # ruleid: python.ssrf
    s.post(body["webhook"])
    # ruleid: python.ssrf
    urllib.request.urlopen(body["feed"])
    # ruleid: python.ssrf
    req = urllib.request.Request(target, headers={"User-Agent": "bot"})
    # ok: python.ssrf
    urllib.request.urlopen("https://feeds.example.com/" + target)
    return "ok"


@app.route("/image")
def image():
    url = request.args["src"]
    # The host is checked against an allow-list; the rule does not recognise the check.
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        return "forbidden", 403
    # todook: python.ssrf
    return requests.get(url).content


# A client made elsewhere (a helper, a parameter, a module global) is not followed.
@app.route("/forward")
def forward_view():
    client = make_client()
    # todoruleid: python.ssrf
    return client.get(request.args["url"]).text


def make_client():
    return httpx.Client(timeout=5)


# Look-alikes: get() of a dict, a cache or the Flask request itself.
CACHE = {}


@app.route("/lookups")
def lookups():
    # ok: python.ssrf
    value = CACHE.get(request.args["key"])
    # ok: python.ssrf
    page = request.args.get("page")
    # ok: python.ssrf
    data = json.loads(request.get_data()).get("x")
    return str((value, page, data))


# Django: the HttpRequest of a view, URL arguments, httpx.
def preview(request, site):
    # ruleid: python.ssrf
    r = httpx.get(request.GET["url"])
    # ruleid: python.ssrf
    httpx.post("http://" + site + "/hook")
    with httpx.Client() as client:
        # ruleid: python.ssrf
        client.get(request.POST["url"], follow_redirects=True)
        # ok: python.ssrf
        client.get("https://api.example.com/sites/" + site)
    # ruleid: python.ssrf
    httpx.request("GET", json.loads(request.body)["url"])
    # ok: python.ssrf
    httpx.get("https://api.example.com/preview", params={"url": request.GET["url"]})
    return HttpResponse(r.text)


class WebhookView(View):
    def post(self, request, hook):
        # ruleid: python.ssrf
        requests.post(self.request.POST["target"], data=b"{}")
        # ruleid: python.ssrf
        requests.post(hook)
        return JsonResponse({"ok": True})


# FastAPI: path and query parameters, bodies, the Request object; httpx.AsyncClient, aiohttp.
class Subscription(BaseModel):
    callback_url: str
    topic: str


@api.post("/subscriptions/{tenant}")
async def subscribe(tenant: str, sub: Subscription, request: Request, ref: str = ""):
    async with httpx.AsyncClient() as client:
        # ruleid: python.ssrf
        await client.post(sub.callback_url, json={"topic": sub.topic})
        # ruleid: python.ssrf
        await client.get(ref)
        # ok: python.ssrf
        await client.get(f"https://api.example.com/tenants/{tenant}/topics")
    async with aiohttp.ClientSession() as session:
        # ruleid: python.ssrf
        async with session.get(request.query_params["feed"]) as resp:
            await resp.text()
        # ruleid: python.ssrf
        async with session.request("GET", "http://" + tenant + ".internal/") as resp:
            await resp.text()
        # ok: python.ssrf
        async with session.get("https://api.example.com/tenants/" + tenant) as resp:
            await resp.text()
    return {"ok": True}


# Fixed origins: a module constant (or Django setting) followed by a "/" path, a constant that
# ends with "host/", and clients with a fixed base_url given a "/" path.
@app.route("/users/<uid>")
def user_profile(uid):
    # ok: python.ssrf
    requests.get(API_BASE + "/users/" + uid)
    # ok: python.ssrf
    requests.get(f"{API_BASE}/users/{uid}/posts/{request.args['page']}")
    # ok: python.ssrf
    requests.get(API_ROOT + uid)
    # ok: python.ssrf
    requests.get("{}/users/{}".format(API_BASE, uid))
    # todook: python.ssrf
    requests.get("%s/users/%s" % (API_BASE, uid))
    # ruleid: python.ssrf
    requests.get(f"{API_BASE}{uid}")
    # ruleid: python.ssrf
    requests.get("//" + uid + "/avatar")
    with requests.Session() as session:
        # ruleid: python.ssrf
        session.get("/" + request.args["next"])
        # ruleid: python.ssrf
        session.get(f"/{request.args['next']}")
        # ok: python.ssrf
        session.get("/users/" + request.args["next"])
    with httpx.Client(base_url=API_BASE) as client:
        # ok: python.ssrf
        client.get(f"/users/{uid}")
        # ruleid: python.ssrf
        client.get(request.args["next"])
    # ruleid: python.ssrf
    httpx.Client(base_url=request.args["upstream"])
    # ruleid: python.ssrf
    requests.Session().get(request.args["next"])
    # ruleid: python.ssrf
    httpx.Client().post(request.args["next"], json={})
    return "ok"


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/short")
def short_url():
    # ruleid: python.ssrf
    requests.get(request.args["url"][:200])
    url = request.args["url"]
    # ruleid: python.ssrf
    requests.get(url[:200], timeout=5)
    # todoruleid: python.ssrf
    requests.get((request.args["url"] + "/")[:200])
    target = request.args["url"]
    target = target.strip()
    # todoruleid: python.ssrf
    requests.get(target[:200])
    return "ok"


@app.route("/partners/<name>")
def partner(name):
    # ok: python.ssrf
    requests.post(MIRRORS.get(name, MIRRORS["eu"]))
    # ok: python.ssrf
    requests.get(STATUS_PAGES[name], timeout=5)
    # ruleid: python.ssrf
    requests.post(PARTNERS.get(name, "https://acme.example.com/hook"))
    HOOKS = {"custom": request.args["hook"]}
    # ruleid: python.ssrf
    requests.post(HOOKS["custom"])
    # ruleid: python.ssrf
    requests.post(MIRRORS.get(name, request.args["fallback"]))
    return "ok"


# Chains after a fixed origin: concatenations, urljoin() of a fixed origin and a relative
# literal, f-strings and format(). Request data before the separator, or as urljoin()'s
# reference, can still change the host.
@app.route("/chains/<uid>")
def chains(uid):
    page = request.args["page"]
    # ok: python.ssrf
    requests.get(API_ROOT + "users/" + uid)
    # ok: python.ssrf
    requests.get(API_ROOT + "users/" + uid + "/posts/" + page)
    # ok: python.ssrf
    requests.get(API_BASE + "/users/" + uid + "/posts/" + page)
    # ok: python.ssrf
    requests.get(API_V2 + "users/" + quote(uid) + "?page=" + page)
    # ok: python.ssrf
    requests.get(API_BASE + "?user=" + uid)
    url = API_ROOT + "users/" + uid
    # ok: python.ssrf
    requests.get(url)
    # ok: python.ssrf
    requests.get(urljoin(API_ROOT, "users/") + uid)
    # ok: python.ssrf
    requests.get(urljoin(API_ROOT, "users/" + uid))
    # ok: python.ssrf
    requests.get(urljoin(API_BASE, "/users/" + uid))
    # ok: python.ssrf
    requests.get(urljoin("https://api.example.com/", "users/" + uid))
    # ok: python.ssrf
    requests.get(urljoin(settings.UPSTREAM_URL, "items/") + uid)
    # ok: python.ssrf
    requests.get(f"{API_ROOT}users/{uid}/posts/{page}")
    # ok: python.ssrf
    requests.get("{}/users/{}/{}".format(API_BASE, uid, page))
    # ok: python.ssrf
    requests.get(settings.UPSTREAM_URL + "/items/" + uid + "/stock")
    # ruleid: python.ssrf
    requests.get(urljoin(API_ROOT, uid))
    # ruleid: python.ssrf
    requests.get(urljoin(API_ROOT, uid) + "/" + page)
    # ruleid: python.ssrf
    requests.get(urljoin(API_BASE, "/" + uid))
    # ruleid: python.ssrf
    requests.get(urljoin("https://api.example.com/", uid))
    # ruleid: python.ssrf
    requests.get(API_BASE + uid + "/posts")
    # ruleid: python.ssrf
    requests.get(f"{API_BASE}{uid}/posts")
    # ruleid: python.ssrf
    requests.get(SCHEME + "//" + uid + "/avatar")
    # A constant that holds only a scheme, or only "/", is no origin: the request value sets the
    # host (uid = "/evil.example").
    # ruleid: python.ssrf
    requests.get(SCHEME + "/" + uid)
    # ruleid: python.ssrf
    requests.get(f"{SCHEME}/{uid}")
    # ruleid: python.ssrf
    requests.get("{}/{}".format(SCHEME, uid))
    # ruleid: python.ssrf
    requests.get(ROOT_PATH + "/" + uid)
    # A longer chain than the rule models.
    # todook: python.ssrf
    requests.get(API_ROOT + "a/" + uid + "/" + page + "/" + page + "/" + page)
    # A literal scheme followed by a host constant.
    # todook: python.ssrf
    requests.get("https://" + API_HOST + "/users/" + uid)
    return "ok"


# A constant imported from a configuration module (or read from the environment) is a fixed
# origin too; an upper-case local that holds request data is not.
@app.route("/config/<uid>")
def config_origin(uid):
    # ok: python.ssrf
    requests.get(CONFIG_API_URL + "/users/" + uid)
    # ok: python.ssrf
    requests.get(f"{ENV_API_URL}/users/{uid}")
    TARGET = request.args["target"]
    # ruleid: python.ssrf
    requests.get(TARGET + "/users/" + uid)
    return "ok"


# A function-local variable that shadows the module constant is not the constant.
@app.route("/shadow/<uid>")
def shadow(uid):
    API_BASE = request.args["base"]
    # ruleid: python.ssrf
    return requests.get(API_BASE + "/users/" + uid).text


# A module constant that a view assigns again (through `global`) is not a fixed origin, before
# or after that view.
UPSTREAM = "https://upstream.example.com"
MIRROR = "https://mirror.example.com"


@app.route("/upstream/<uid>")
def upstream(uid):
    # ruleid: python.ssrf
    return requests.get(UPSTREAM + "/users/" + uid).text


@app.post("/upstream")
def set_upstream():
    global UPSTREAM, MIRROR
    UPSTREAM = request.form["url"]
    MIRROR = request.form["mirror"]
    return "ok"


@app.route("/mirror/<uid>")
def mirror(uid):
    # ruleid: python.ssrf
    return requests.get(MIRROR + "/users/" + uid).text


@app.post("/partners")
def add_partner():
    PARTNERS[request.form["name"]] = request.form["url"]
    return "ok"


# Flask typed converter: the rule cannot see that <int:port> is an int.
@app.route("/local/<int:port>")
def local_port(port):
    # todook: python.ssrf
    return requests.get("http://127.0.0.1:%s/health" % port).text


def django_upstream(request, item):
    # ok: python.ssrf
    r = httpx.get(f"{settings.UPSTREAM_URL}/items/{item}")
    # ok: python.ssrf
    r = httpx.get(settings.UPSTREAM_URL + "/items/" + request.GET["id"])
    return HttpResponse(r.text)


# path("ports/<int:pk>/", views.django_port): the converter is in urls.py.
def django_port(request, pk):
    # todook: python.ssrf
    return HttpResponse(requests.get("http://127.0.0.1:%s/" % pk).text)


# A function named like a class-based view's handler (get, post, ...) that takes (self, request,
# ...) is taken for one also outside a class: its parameters after request count as URL arguments.
def get(self, request, pk):
    # todook: python.ssrf
    return HttpResponse(requests.get("http://127.0.0.1:%s/" % pk).text)


# A default value: Django passes the URL value when the pattern captures one.
def django_status(request, host="localhost"):
    # todook: python.ssrf
    return HttpResponse(requests.get("http://" + host + "/status").text)


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def fetch_for(request, target_url):
    # todook: python.ssrf
    return requests.get(target_url)


def follow_location(request):
    # todook: python.ssrf
    return requests.get(request.headers["Location"])


class Settings(BaseModel):
    webhook_url: str = "https://hooks.example.com/"


def get_settings():
    return Settings()


# FastAPI's Annotated form, in place or through an alias.
SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/annotated/{port}")
async def annotated(
    port: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    target: Annotated[str, Query()] = "",
):
    # ok: python.ssrf
    httpx.post(settings.webhook_url, json={"port": port})
    # ok: python.ssrf
    httpx.post(other.webhook_url)
    # ok: python.ssrf
    httpx.get("http://127.0.0.1:%d/" % port)
    # ruleid: python.ssrf
    return httpx.get(target).text


# A Flask view parameter annotated int is no longer a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_host>")
def legacy(legacy_host: int):
    # todoruleid: python.ssrf
    return requests.get("http://" + legacy_host + "/status").text


# FastAPI converts int parameters; Depends() parameters are dependencies, not request data.
@api.get("/ports/{port}")
async def port_status(port: int, callback: str = "", settings: Settings = Depends(get_settings)):
    # ok: python.ssrf
    httpx.get("http://127.0.0.1:%d/health" % port)
    # ok: python.ssrf
    httpx.post(settings.webhook_url, json={"port": port})
    async with aiohttp.ClientSession(API_BASE) as session:
        # ok: python.ssrf
        async with session.get("/ports/" + str(port)) as resp:
            await resp.text()
    # ruleid: python.ssrf
    async with aiohttp.request("GET", callback) as resp:
        await resp.text()
    return {"ok": True}
